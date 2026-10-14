//! v56.0.0 (CIRISPersist#1001) — **I900–I906 + I913: the typed bounded read.**
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
//! - **I904** (in `observe/tests.rs`) the read is recorded in ONE place, the
//!   shared wrapper.
//! - **I905** *error is not empty* (CSD/3 rule 3): a backend fault and a
//!   refused read come back `NotServed` (with the reason's kind), an
//!   unmatched filter comes back `Served` with zero rows, on all three
//!   backends.
//! - **I913** `DimensionFilter::AnyOf` returns exactly the rows whose
//!   dimension is one of the set (two members present, one absent), and
//!   `ScopeFilter` exactly the rows of the `cohort_scope` (and, when given,
//!   the `cohort_target`), on `by` and `to` queries and combined with a
//!   dimension prefix — as I900 shapes, so they page, order and seek like
//!   every other shape (I901/I903). An empty `AnyOf` is refused (I902).
//! - **I906** `as_of(t)` keeps exactly the rows whose SIGNED `asserted_at <=
//!   t`, in `ByAssertedAt` order with the id tie-break, both directions,
//!   paged; a row landed AFTER the read, dated after `t`, never enters the
//!   replay, and one dated at or before `t` does (the bound is the signer's
//!   instant, not receipt time). Sqlite and postgres keep it one LIMITed
//!   statement on an index.
//!
//! [`AttestationQuery::admits`]: super::attestation_query::AttestationQuery::admits
//! [`MAX_PAGE`]: super::attestation_query::MAX_PAGE

#[cfg(test)]
pub(crate) mod bodies {
    use std::num::NonZeroU32;

    use crate::federation::attestation_query::{
        AttestationQuery, AttestationQueryExec, AttestationReads, NotServedReason, QueryRows,
        QueryTier, ReadOutcome,
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
        /// The stored `cohort_scope`.
        pub scope: String,
        /// The envelope's cohort target (V150's generated column).
        pub target: Option<String>,
    }

    /// The corpus: three keys, every type/dimension shape a query narrows
    /// on, asserted-at ties, and one local-tier row.
    pub struct Corpus {
        pub a: String,
        pub b: String,
        pub c: String,
        /// Two community ids the scoped rows target (I913).
        pub comm1: String,
        pub comm2: String,
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
        put_scoped(d, by, to, dimension, minute, None).await
    }

    /// A `scores` row; `scope` = `(cohort_scope, community_id)` stamps the
    /// row's visibility scope and (when given) its envelope cohort target.
    async fn put_scoped(
        d: &dyn FederationDirectory,
        by: &str,
        to: &str,
        dimension: &str,
        minute: i64,
        scope: Option<(&str, Option<&str>)>,
    ) -> Row {
        let id = uuid::Uuid::new_v4().to_string();
        let mut env = serde_json::json!({ "dimension": dimension, "id": id });
        if let Some((_, Some(target))) = scope {
            env["community_id"] = serde_json::Value::String(target.to_owned());
        }
        let mut r = ts::bare_attestation(&id, by, to, &env);
        if let Some((cohort_scope, _)) = scope {
            r.cohort_scope = cohort_scope.to_owned();
        }
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
            scope: r.cohort_scope.clone(),
            target: crate::federation::cohort_target_of_envelope(&r.attestation_envelope)
                .map(str::to_owned),
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
        rows.push(put_scores(d, &a, &a, "i900x:a:v1", -60).await);
        rows.push(put_scores(d, &a, &a, "i900x:a2:v1", -50).await);
        rows.push(put_scores(d, &a, &a, "i900x:a3:v1", -50).await);
        rows.push(put_scores(d, &a, &a, "i900x:b:v1", -40).await);
        rows.push(put_scores(d, &a, &a, "i900x:b2:v1", -30).await);
        rows.push(put_scores(d, &a, &a, "other:x:v1", -20).await);
        // A about B and C, one tied with A's config:b2.
        rows.push(put_scores(d, &a, &b, "i900x:a:v1", -30).await);
        rows.push(put_scores(d, &a, &b, "i900x:ab:v1", -10).await);
        rows.push(put_scores(d, &a, &c, "i900x:a:v1", -25).await);
        // B about A.
        rows.push(put_scores(d, &b, &a, "i900x:c:v1", -45).await);
        rows.push(put_scores(d, &b, &a, "i900x:c2:v1", -5).await);
        // I913 — scoped rows: two communities, one species-wide row.
        let comm1 = format!("i900-comm1-{s}");
        let comm2 = format!("i900-comm2-{s}");
        let community = crate::federation::types::cohort_scope::COMMUNITY;
        let species = crate::federation::types::cohort_scope::SPECIES;
        rows.push(
            put_scoped(
                d,
                &a,
                &a,
                "i900s:a:v1",
                -48,
                Some((community, Some(&comm1))),
            )
            .await,
        );
        rows.push(
            put_scoped(
                d,
                &a,
                &a,
                "i900s:b:v1",
                -12,
                Some((community, Some(&comm2))),
            )
            .await,
        );
        rows.push(put_scoped(d, &b, &a, "i900s:c:v1", -8, Some((community, Some(&comm1)))).await);
        rows.push(put_scoped(d, &a, &b, "i900s:d:v1", -22, Some((species, None))).await);
        // C noise.
        for (leaf, m) in [
            ("i900x:a:v1", -55),
            ("i900x:a2:v1", -35),
            ("i900x:a3:v1", -15),
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
                    serde_json::json!({ "dimension": "i900x:a:v1" }),
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
            .served()
            .expect("local read")
            .rows;
        assert_eq!(local.len(), 1, "I900 one local row");
        assert_eq!(local[0].attestation_id, local_id);
        rows.push(Row {
            id: local_id,
            by: a.clone(),
            to: a.clone(),
            kind: attestation_type::SCORES.into(),
            dimension: Some("i900x:a:v1".into()),
            at: local[0].asserted_at,
            local: true,
            scope: crate::federation::types::cohort_scope::SELF.to_owned(),
            target: None,
        });
        let _ = read_probe::take();
        Corpus {
            a,
            b,
            c,
            comm1,
            comm2,
            rows,
        }
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
                o(AttestationQuery::by(a, lim).dimension_prefix("i900x:")),
                expect(corpus, |r| fed(r) && r.by == a && dim(r, "i900x:"), oldest),
            ));
            out.push((
                "by A, exact config:a:v1",
                o(AttestationQuery::by(a, lim).dimension("i900x:a:v1")),
                expect(
                    corpus,
                    |r| fed(r) && r.by == a && r.dimension.as_deref() == Some("i900x:a:v1"),
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
                    .excluding_dimensions(&["i900x:a:v1"])),
                expect(
                    corpus,
                    |r| fed(r) && r.by == a && r.dimension.as_deref() != Some("i900x:a:v1"),
                    oldest,
                ),
            ));
            out.push((
                "by A excluding config:a:v1 (no type)",
                o(AttestationQuery::by(a, lim).excluding_dimensions(&["i900x:a:v1"])),
                expect(
                    corpus,
                    |r| fed(r) && r.by == a && r.dimension.as_deref() != Some("i900x:a:v1"),
                    oldest,
                ),
            ));
            out.push((
                "to B by A prefix config:a",
                o(AttestationQuery::to(b, lim)
                    .authored_by(a)
                    .dimension_prefix("i900x:a")),
                expect(
                    corpus,
                    |r| fed(r) && r.to == b && r.by == a && dim(r, "i900x:a"),
                    oldest,
                ),
            ));
            out.push((
                "by A, type prefix wi",
                o(AttestationQuery::by(a, lim).type_prefix("wi")),
                expect(
                    corpus,
                    |r| fed(r) && r.by == a && r.kind.starts_with("wi"),
                    oldest,
                ),
            ));
            out.push((
                "to A, type prefix sc",
                o(AttestationQuery::to(a, lim).type_prefix("sc")),
                expect(
                    corpus,
                    |r| fed(r) && r.to == a && r.kind.starts_with("sc"),
                    oldest,
                ),
            ));
            // I913 — DimensionFilter::AnyOf: exact dimensions OR'd.
            out.push((
                "by A, any of config:a:v1 / config:b2:v1",
                o(AttestationQuery::by(a, lim).dimension_any_of(&["i900x:a:v1", "i900x:b2:v1"])),
                expect(
                    corpus,
                    |r| {
                        fed(r)
                            && r.by == a
                            && matches!(r.dimension.as_deref(), Some("i900x:a:v1" | "i900x:b2:v1"))
                    },
                    oldest,
                ),
            ));
            out.push((
                "to B, any of config:a:v1 / config:ab:v1 / absent",
                o(AttestationQuery::to(b, lim).dimension_any_of(&[
                    "i900x:a:v1",
                    "i900x:ab:v1",
                    "i900x:none:v1",
                ])),
                expect(
                    corpus,
                    |r| {
                        fed(r)
                            && r.to == b
                            && matches!(r.dimension.as_deref(), Some("i900x:a:v1" | "i900x:ab:v1"))
                    },
                    oldest,
                ),
            ));
            // I913 — ScopeFilter: cohort_scope, and cohort_target when given.
            let (c1, c2) = (corpus.comm1.as_str(), corpus.comm2.as_str());
            let community = crate::federation::types::cohort_scope::COMMUNITY;
            let species = crate::federation::types::cohort_scope::SPECIES;
            out.push((
                "to A, scope community",
                o(AttestationQuery::to(a, lim).scope(community, None)),
                expect(
                    corpus,
                    |r| fed(r) && r.to == a && r.scope == community,
                    oldest,
                ),
            ));
            out.push((
                "to A, scope community comm1",
                o(AttestationQuery::to(a, lim).scope(community, Some(c1))),
                expect(
                    corpus,
                    |r| {
                        fed(r)
                            && r.to == a
                            && r.scope == community
                            && r.target.as_deref() == Some(c1)
                    },
                    oldest,
                ),
            ));
            out.push((
                "by A, scope community",
                o(AttestationQuery::by(a, lim).scope(community, None)),
                expect(
                    corpus,
                    |r| fed(r) && r.by == a && r.scope == community,
                    oldest,
                ),
            ));
            out.push((
                "by A, scope species",
                o(AttestationQuery::by(a, lim).scope(species, None)),
                expect(
                    corpus,
                    |r| fed(r) && r.by == a && r.scope == species,
                    oldest,
                ),
            ));
            out.push((
                "by A, prefix i900s: + scope community comm2",
                o(AttestationQuery::by(a, lim)
                    .dimension_prefix("i900s:")
                    .scope(community, Some(c2))),
                expect(
                    corpus,
                    |r| {
                        fed(r)
                            && r.by == a
                            && dim(r, "i900s:")
                            && r.scope == community
                            && r.target.as_deref() == Some(c2)
                    },
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
            let page = d.query_attestations(&q).await.served().expect("page");
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
            ReadOutcome::NotServed(NotServedReason::Fault(Error::Backend(m))) => {
                assert!(m.contains("past its page"), "{m}");
            }
            other => panic!("I902 an over-returning executor is refused, got {other:?}"),
        }
        let refused = |o: ReadOutcome| {
            matches!(
                o,
                ReadOutcome::NotServed(NotServedReason::Refused(Error::InvalidArgument(_)))
            )
        };
        let mut unpinned = q.clone();
        unpinned.by = None;
        assert!(refused(d.query_attestations(&unpinned).await));
        let mut huge = q.clone();
        huge.limit = NonZeroU32::new(crate::federation::attestation_query::MAX_PAGE + 1).unwrap();
        assert!(refused(d.query_attestations(&huge).await));
        // I913 — an empty AnyOf names no dimension: refused, never "any"
        // and never an empty page.
        assert!(refused(
            d.query_attestations(&q.clone().dimension_any_of(&[])).await
        ));
        let page = d.query_attestations(&q).await.served().unwrap();
        let mut c = page.next.expect("A has more than one row");
        c.version = "v0".into();
        assert!(refused(
            d.query_attestations(&q.clone().after(Some(c))).await
        ));
    }

    /// **I905** — error is not empty. `d` is the real backend; it is wrapped
    /// in the fault double for the fault and the proxy refusal.
    pub async fn i905_not_served_is_never_an_empty_page(
        d: std::sync::Arc<dyn FederationDirectory>,
        s: &str,
    ) {
        use crate::federation::directory_double::FaultInjectingDirectory;
        let corpus = seed(&*d, s).await;
        // Served, zero rows: the filter matches nothing.
        let unmatched = AttestationQuery::by(&corpus.a, NonZeroU32::MIN).dimension("i905:never:v1");
        match d.query_attestations(&unmatched).await {
            ReadOutcome::Served(p) => {
                assert!(p.rows.is_empty() && p.next.is_none(), "I905 {p:?}");
            }
            other => panic!("I905 an unmatched filter is Served(empty), got {other:?}"),
        }
        // And an unknown key: still Served(empty).
        let nobody = AttestationQuery::to(&format!("i905-nobody-{s}"), NonZeroU32::MIN);
        assert!(matches!(
            d.query_attestations(&nobody).await,
            ReadOutcome::Served(ref p) if p.rows.is_empty()
        ));
        // A matching query, for the faults below: Served with rows.
        let q = AttestationQuery::by(&corpus.a, NonZeroU32::MIN);
        assert!(matches!(
            d.query_attestations(&q).await,
            ReadOutcome::Served(ref p) if p.rows.len() == 1
        ));
        // A backend fault: NotServed(Fault), never Served(empty).
        let faulting =
            FaultInjectingDirectory::new(d.clone()).erroring("execute_attestation_query");
        match faulting.query_attestations(&q).await {
            ReadOutcome::NotServed(NotServedReason::Fault(Error::Backend(m))) => {
                assert!(m.contains("injected"), "{m}");
            }
            other => panic!("I905 a backend fault is NotServed(Fault), got {other:?}"),
        }
        // The `?` form propagates it as an error, not as zero rows.
        assert!(faulting.query_attestations(&q).await.served().is_err());
        let mut pages = q.clone().pages();
        assert!(
            pages.next(&faulting).await.is_err(),
            "I905 a fold sees the fault"
        );
        // A directory that does not serve the read (a proxy): NotServed(Refused).
        let proxy =
            FaultInjectingDirectory::new(d.clone()).unsupported("execute_attestation_query");
        assert!(matches!(
            proxy.query_attestations(&q).await,
            ReadOutcome::NotServed(NotServedReason::Refused(Error::Unsupported { .. }))
        ));
        // A refused query (no pinned key): NotServed(Refused), on the real
        // backend.
        let mut unpinned = q.clone();
        unpinned.by = None;
        assert!(matches!(
            d.query_attestations(&unpinned).await,
            ReadOutcome::NotServed(NotServedReason::Refused(Error::InvalidArgument(_)))
        ));
    }

    /// **I906** — `as_of` replays by the signed instant.
    pub async fn i906_as_of_replays_by_the_signed_instant(d: &dyn FederationDirectory, s: &str) {
        let corpus = seed(d, s).await;
        let a = corpus.a.clone();
        let fed_by_a = |r: &Row| !r.local && r.by == a;
        // Cut points: before everything, on a tie (-50: two rows), between
        // rows, and after everything.
        let cuts = [-61_i64, -50, -26, 0];
        for minute in cuts {
            let t = base() + chrono::Duration::minutes(minute);
            for oldest in [false, true] {
                let mut q = AttestationQuery::by(&a, NonZeroU32::MIN).as_of(t);
                if oldest {
                    q = q.oldest_first();
                }
                let want = expect(&corpus, |r| fed_by_a(r) && r.at <= t, oldest);
                for limit in [1, 2, 50] {
                    let got = page_through(d, q.clone(), limit, want.len(), "I906").await;
                    assert_eq!(
                        got, want,
                        "I906 as_of {minute} (limit {limit}, oldest {oldest})"
                    );
                }
            }
        }
        // Replay: the as-of(-26) view, read now.
        let t = base() + chrono::Duration::minutes(-26);
        let q = AttestationQuery::by(&a, NonZeroU32::new(50).unwrap()).as_of(t);
        let before = d.query_attestations(&q).await.served().unwrap().rows;
        // A row RECEIVED now but SIGNED at -40 (inside the view) enters it; a
        // row received now and signed at -25 (after t) does not — even though
        // both landed after the first read.
        let inside = put_scores(d, &a, &corpus.b, "i900x:i906in:v1", -40).await;
        let outside = put_scores(d, &a, &corpus.b, "i900x:i906out:v1", -25).await;
        let after = d.query_attestations(&q).await.served().unwrap().rows;
        let ids: Vec<&str> = after.iter().map(|r| r.attestation_id.as_str()).collect();
        assert!(
            ids.contains(&inside.id.as_str()),
            "I906 a row dated <= t is in the view"
        );
        assert!(
            !ids.contains(&outside.id.as_str()),
            "I906 a row dated > t never enters the as-of view"
        );
        assert_eq!(
            after.len(),
            before.len() + 1,
            "I906 only the inside row joined"
        );
        // The order is the signed instant, ties by id: recompute by hand.
        let mut sorted = after.clone();
        sorted.sort_by(|x, y| {
            (y.asserted_at, y.attestation_id.as_str())
                .cmp(&(x.asserted_at, x.attestation_id.as_str()))
        });
        assert_eq!(after, sorted, "I906 ByAssertedAt(Desc), id tie-break");
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
                async fn i905_not_served_is_never_an_empty_page() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i905_not_served_is_never_an_empty_page(
                        std::sync::Arc::new(d),
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i906_as_of_replays_by_the_signed_instant() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i906_as_of_replays_by_the_signed_instant(
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
        // And every shape with a cursor.
        let cursor: Vec<_> = shapes
            .iter()
            .map(|(_, q, _)| {
                let c = crate::ceg::list::federation::AttestationCursor::from_trailing(
                    chrono::Utc::now(),
                    "x".into(),
                );
                ("cursor", q.clone().after(Some(c)), vec![])
            })
            .collect();
        shapes.extend(cursor);
        // And every shape as of an instant (I906): one more range term on
        // the same index.
        let as_of: Vec<_> = shapes
            .iter()
            .map(|(_, q, _)| ("as_of", q.clone().as_of(chrono::Utc::now()), vec![]))
            .collect();
        shapes.extend(as_of);
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
        let mut shapes = super::bodies::shapes(&corpus);
        let as_of: Vec<_> = shapes
            .iter()
            .map(|(_, q, _)| ("as_of", q.clone().as_of(chrono::Utc::now()), vec![]))
            .collect();
        shapes.extend(as_of);
        for (tag, q, _) in shapes {
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
