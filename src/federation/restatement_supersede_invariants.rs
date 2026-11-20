//! v62.0.0 (v62 P8-fix14; lead ruling (a), CC 4.4.3.3.1 / 8.1.5) — **I3540,
//! I3548: an edition-2 restatement hides the prior it widens.** sqlite and
//! postgres.
//!
//! A widening restates the claim as a NEW row (`crossing::widen_by_restatement`);
//! no composer names the prior. Both rows carry the restatement key their
//! statements derive (`crossing::restatement_key`, V300's `restatement_key`
//! column), and the Live read hides a row while a live row by the SAME
//! attester with the same key holds an audience that strictly CONTAINS its
//! own (`attestation_query::lifecycle_predicate`).
//!
//! - **I3540** — on one node:
//!   - before the widening the `self` prior is live;
//!   - after widening it to `federation`, the restatement is live and the
//!     prior is hidden;
//!   - NARROWING is the author's `withdraws` of the wider row: the wider row
//!     is no longer served and the narrower prior is served again;
//!   - a restatement of the same claim by ANOTHER key (another `iss`, so
//!     another restatement key) hides nothing: refused at the door or
//!     stored, the prior stays live;
//!   - family → community: both stay live. The two audiences are
//!     incomparable, so the containment rule hides neither. This is checked
//!     on the Live fragment itself, with the two rows' scopes moved beneath
//!     every door after a widening.
//! - **I3548** — the replica case: a third node that receives both
//!   statements, prior first or restatement first, reads the same Live set
//!   (only the restatement). The hide is a read-time predicate over held
//!   rows, so arrival order cannot matter.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::composer_rank_invariants::bodies as cr;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type;
    use crate::federation::{
        Attestation, Audience, CrossingBasis, FederationDirectory, MeshCrossingOutcome,
    };

    /// Widen `prior` to `federation` by restatement; the restatement row.
    async fn widen(d: &dyn FederationDirectory, prior: &Attestation) -> Attestation {
        let ci = ts::describe_for(
            prior,
            Audience::Federation,
            CrossingBasis::ProducerAuthority,
        );
        let out = crate::federation::crossing::widen_by_restatement(
            d,
            prior,
            &ci,
            &ts::local_signer(&prior.attesting_key_id),
            &[],
        )
        .await
        .expect("the widening");
        let MeshCrossingOutcome::Crossed(report) = out else {
            panic!("a widening crosses: {out:?}");
        };
        d.get_attestation(&report.attestation_id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("restatement {} is stored", report.attestation_id))
    }

    fn key_of(row: &Attestation) -> Option<String> {
        crate::federation::crossing::restatement_key_of_row(row)
    }

    /// The key never reaches a content hash: the stored row's envelope
    /// carries no restatement member, and its `original_content_hash` and
    /// `persist_row_hash` are exactly what the door's mapping
    /// (`ingest::attestation_of`, unchanged by P8-fix14) computes for its
    /// statement.
    fn assert_hashes_untouched(row: &Attestation, what: &str) {
        let st = e2::carried_statement(row).expect("an edition-2 row");
        let mapped = e2::row_of_statement(&st, &row.tier);
        assert!(
            row.attestation_envelope
                .as_object()
                .is_some_and(|o| o.keys().all(|k| !k.contains("restatement"))),
            "{what}: no restatement member in the envelope"
        );
        assert_eq!(
            row.original_content_hash, mapped.original_content_hash,
            "{what}: original_content_hash is the mapping's"
        );
        assert_eq!(
            row.persist_row_hash, mapped.persist_row_hash,
            "{what}: persist_row_hash is the mapping's"
        );
    }

    /// I3540.
    pub(crate) async fn i3540_a_restatement_hides_its_prior<B>(d: &B, s: &str)
    where
        B: FederationDirectory + crate::read::ReadEngine,
    {
        let author = format!("i3540-a-{s}");
        let other = format!("i3540-o-{s}");
        for k in [&author, &other] {
            ts::register_hybrid_key_as(d, k, k, identity_type::USER).await;
        }
        let prior = cr::self_row(d, &author).await;
        assert!(
            cr::live_ids(d, &author)
                .await
                .contains(&prior.attestation_id),
            "I3540: the prior is live before any widening"
        );
        let w = widen(d, &prior).await;
        assert_ne!(w.attestation_id, prior.attestation_id, "I3540: a new row");
        assert!(key_of(&prior).is_some(), "I3540: the prior carries its key");
        assert_hashes_untouched(&prior, "I3540 (prior)");
        assert_hashes_untouched(&w, "I3540 (restatement)");
        assert_eq!(
            key_of(&w),
            key_of(&prior),
            "I3540: the restatement shares the prior's key"
        );
        let live = cr::live_ids(d, &author).await;
        assert!(
            live.contains(&w.attestation_id),
            "I3540: the restatement is current ({live:?})"
        );
        assert!(
            !live.contains(&prior.attestation_id),
            "I3540: the prior is no longer current ({live:?})"
        );

        // Narrowing: the author withdraws the wider row.
        crate::federation::subject_erasure_invariants::bodies::put_withdraws_as(d, &author, &w)
            .await
            .expect("I3540: the author withdraws the wider row");
        let live = cr::live_ids(d, &author).await;
        assert!(
            !live.contains(&w.attestation_id),
            "I3540: the wider row is no longer served after the narrowing ({live:?})"
        );
        assert!(
            live.contains(&prior.attestation_id),
            "I3540: the narrower prior is served again ({live:?})"
        );

        // A non-author's restatement of the same claim hides nothing.
        let r =
            crate::federation::crossing::restate_at_audience(&prior, &Audience::Federation, &[])
                .expect("the claim restated");
        let st = ciris_verify_core::edition2::sign_row_statement(
            &e2::signing_key(&other),
            &e2::kid(&other),
            &prior.attested_key_id,
            &r.row_type,
            &r.family,
            &r.payload,
            vec![],
        )
        .expect("another key signs the same claim");
        let _held_or_refused = crate::federation::edition2::ingest::put_statement(
            d,
            &st,
            None,
            crate::federation::edition2::ingest::INGEST_TIER,
        )
        .await;
        assert!(
            cr::live_ids(d, &author)
                .await
                .contains(&prior.attestation_id),
            "I3540: another key's restatement does not supersede the author's prior"
        );
    }

    /// I3540 (family → community) — the predicate's containment, read at the
    /// SQL level: after a widening, the prior's and the restatement's scopes
    /// are moved beneath every door to `family` and `community` (incomparable
    /// audiences), and the Live fragment then keeps BOTH; before the move it
    /// keeps only the restatement (the control). `ids(dialect)` runs the
    /// author's rows through `lifecycle_predicate(Live)`; `set_scope` moves
    /// one row's `cohort_scope`.
    pub(crate) async fn i3540_family_and_community_both_stay_live<B, Q, QF, S, SF>(
        d: &B,
        s: &str,
        ids: Q,
        set_scope: S,
    ) where
        B: FederationDirectory + crate::read::ReadEngine,
        Q: Fn(String) -> QF,
        QF: std::future::Future<Output = Vec<String>>,
        S: Fn(String, &'static str) -> SF,
        SF: std::future::Future<Output = ()>,
    {
        let author = format!("i3540f-a-{s}");
        ts::register_hybrid_key_as(d, &author, &author, identity_type::USER).await;
        let prior = cr::self_row(d, &author).await;
        let w = widen(d, &prior).await;
        let kid = e2::kid(&author);
        let mut want = vec![w.attestation_id.clone()];
        assert_eq!(
            ids(kid.clone()).await,
            want,
            "I3540 (control): the Live fragment keeps only the restatement"
        );
        set_scope(prior.attestation_id.clone(), "family").await;
        set_scope(w.attestation_id.clone(), "community").await;
        want.push(prior.attestation_id.clone());
        want.sort();
        let mut got = ids(kid).await;
        got.sort();
        assert_eq!(
            got, want,
            "I3540: family and community are incomparable: both stay live"
        );
    }

    /// v62.0.0 (P8-fix16) — a crossed `self` row of `author` and its
    /// widening restatement, written on `d`; the author's identity-ref.
    pub(crate) async fn stated_pair<B>(d: &B, author: &str) -> String
    where
        B: FederationDirectory + crate::read::ReadEngine,
    {
        ts::register_hybrid_key_as(d, author, author, identity_type::USER).await;
        let prior = cr::self_row(d, author).await;
        widen(d, &prior).await;
        e2::kid(author)
    }

    /// I3548 — both statements reach a third node `c`, in `prior_first`
    /// order or the reverse.
    pub(crate) async fn i3548_a_replica_converges<B>(a: &B, c: &B, s: &str, prior_first: bool)
    where
        B: FederationDirectory + crate::read::ReadEngine,
    {
        let author = format!("i3548-a-{s}");
        for d in [a, c] {
            ts::register_hybrid_key_as(d, &author, &author, identity_type::USER).await;
        }
        let prior = cr::self_row(a, &author).await;
        let w = widen(a, &prior).await;
        let statements = [
            e2::carried_statement(&prior).expect("the prior's statement"),
            e2::carried_statement(&w).expect("the restatement's statement"),
        ];
        let order: Vec<&Vec<u8>> = if prior_first {
            statements.iter().collect()
        } else {
            statements.iter().rev().collect()
        };
        for st in order {
            crate::federation::edition2::ingest::put_statement(
                c,
                st,
                None,
                crate::federation::edition2::ingest::INGEST_TIER,
            )
            .await
            .unwrap_or_else(|e| panic!("I3548: the third node admits the statement: {e:?}"));
        }
        assert!(
            c.get_attestation(&prior.attestation_id)
                .await
                .unwrap()
                .is_some(),
            "I3548: the third node holds the prior"
        );
        let live = cr::live_ids(c, &author).await;
        assert!(
            live.contains(&w.attestation_id) && !live.contains(&prior.attestation_id),
            "I3548 (prior_first={prior_first}): only the restatement is current on the replica \
             ({live:?})"
        );
        assert_eq!(
            live,
            cr::live_ids(a, &author).await,
            "I3548: the replica reads what the origin reads"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    /// v62.0.0 (P8-fix16) — I3523c, sqlite: every row a mapped edition-2
    /// statement wrote (the crossed `self` row and its restatement, both
    /// carrying `ceg_statement`) has a non-null `restatement_key`.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i3523c_every_edition2_row_carries_its_key_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let author = format!(
            "i3523c-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        );
        let kid = super::bodies::stated_pair(&b, &author).await;
        let (keyed, unkeyed): (i64, i64) = b
            .conn_handle()
            .lock()
            .query_row(
                "SELECT \
                   SUM(CASE WHEN restatement_key IS NOT NULL THEN 1 ELSE 0 END), \
                   SUM(CASE WHEN restatement_key IS NULL THEN 1 ELSE 0 END) \
                 FROM federation_attestations \
                 WHERE attesting_key_id = ?1 \
                   AND json_extract(attestation_envelope, '$.ceg_statement') IS NOT NULL",
                [&kid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("count");
        assert!(
            keyed >= 2,
            "I3523c: the prior and its restatement are keyed ({keyed})"
        );
        assert_eq!(
            unkeyed, 0,
            "I3523c: no edition-2 row is written without its key"
        );
    }

    /// I3523c, postgres.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i3523c_every_edition2_row_carries_its_key_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("i3523c postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let author = format!(
            "i3523c-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        );
        let kid = super::bodies::stated_pair(&b, &author).await;
        let c = crate::store::postgres::dedicated_connect_to(&dsn)
            .await
            .expect("connect");
        let r = c
            .query_one(
                "SELECT \
                   count(*) FILTER (WHERE restatement_key IS NOT NULL), \
                   count(*) FILTER (WHERE restatement_key IS NULL) \
                 FROM cirislens.federation_attestations \
                 WHERE attesting_key_id = $1 \
                   AND (attestation_envelope)::jsonb ? 'ceg_statement'",
                &[&kid],
            )
            .await
            .expect("count");
        let (keyed, unkeyed): (i64, i64) = (r.get(0), r.get(1));
        assert!(
            keyed >= 2,
            "I3523c: the prior and its restatement are keyed ({keyed})"
        );
        assert_eq!(
            unkeyed, 0,
            "I3523c: no edition-2 row is written without its key"
        );
        eprintln!("i3523c postgres: RAN");
    }

    /// I3540 (family → community), sqlite: the Live fragment run directly.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i3540_family_and_community_sqlite() {
        use crate::federation::attestation_query::{lifecycle_predicate, Dialect};
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let ids = |kid: String| {
            let conn = b.conn_handle();
            async move {
                let (pred, types) =
                    lifecycle_predicate(crate::read::LifecycleView::Live, Dialect::Sqlite, "fa", 2)
                        .expect("Live hides");
                let sql = format!(
                    "SELECT fa.attestation_id FROM federation_attestations fa \
                     WHERE fa.attesting_key_id = ?1 AND {pred} ORDER BY fa.attestation_id"
                );
                let mut binds: Vec<String> = vec![kid];
                binds.extend(types);
                let c = conn.lock();
                let mut st = c.prepare(&sql).expect("prepare");
                st.query_map(rusqlite::params_from_iter(binds.iter()), |r| {
                    r.get::<_, String>(0)
                })
                .expect("query")
                .collect::<Result<Vec<_>, _>>()
                .expect("rows")
            }
        };
        let set_scope = |id: String, scope: &'static str| {
            let b = &b;
            async move {
                b.test_execute(&format!(
                    "UPDATE federation_attestations SET cohort_scope = '{scope}' \
                     WHERE attestation_id = '{id}'"
                ))
                .await;
            }
        };
        super::bodies::i3540_family_and_community_both_stay_live(
            &b,
            &uuid::Uuid::new_v4().simple().to_string()[..12],
            ids,
            set_scope,
        )
        .await;
    }

    /// I3540 (family → community), postgres.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i3540_family_and_community_postgres() {
        use crate::federation::attestation_query::{lifecycle_predicate, Dialect};
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("i3540 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let ids = |kid: String| {
            let dsn = dsn.clone();
            async move {
                let (pred, types) = lifecycle_predicate(
                    crate::read::LifecycleView::Live,
                    Dialect::Postgres,
                    "fa",
                    2,
                )
                .expect("Live hides");
                let sql = format!(
                    "SELECT fa.attestation_id::text FROM cirislens.federation_attestations fa \
                     WHERE fa.attesting_key_id = $1 AND {pred} ORDER BY 1"
                );
                let c = crate::store::postgres::dedicated_connect_to(&dsn)
                    .await
                    .expect("connect");
                let mut binds: Vec<String> = vec![kid];
                binds.extend(types);
                let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = binds
                    .iter()
                    .map(|v| v as &(dyn tokio_postgres::types::ToSql + Sync))
                    .collect();
                c.query(sql.as_str(), &params)
                    .await
                    .expect("query")
                    .iter()
                    .map(|r| r.get::<_, String>(0))
                    .collect()
            }
        };
        let set_scope = |id: String, scope: &'static str| {
            let b = &b;
            async move {
                b.test_execute(&format!(
                    "UPDATE cirislens.federation_attestations SET cohort_scope = '{scope}' \
                     WHERE attestation_id = '{id}'"
                ))
                .await;
            }
        };
        super::bodies::i3540_family_and_community_both_stay_live(
            &b,
            &uuid::Uuid::new_v4().simple().to_string()[..12],
            ids,
            set_scope,
        )
        .await;
        eprintln!("i3540 family/community postgres: RAN");
    }

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                #[tokio::test]
                async fn i3540_a_restatement_hides_its_prior() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i3540_a_restatement_hides_its_prior(&d, &suffix()).await
                }
                #[tokio::test]
                async fn i3548_a_replica_converges_prior_first() {
                    let Some(a) = $fresh.await else { return };
                    let Some(c) = $fresh.await else { return };
                    super::super::bodies::i3548_a_replica_converges(&a, &c, &suffix(), true).await
                }
                #[tokio::test]
                async fn i3548_a_replica_converges_restatement_first() {
                    let Some(a) = $fresh.await else { return };
                    let Some(c) = $fresh.await else { return };
                    super::super::bodies::i3548_a_replica_converges(&a, &c, &suffix(), false).await
                }
            }
        };
    }

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
        let dsn = crate::test_pg::isolated_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
