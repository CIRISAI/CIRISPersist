//! v61.1.0 (CIRISPersist#1190, #1163) — **I1570–I1579 and I1670–I1675: the
//! narrowed serve read and the owner-binding feed**, on sqlite and postgres,
//! through [`FederationDirectory::list_attestations_since_by_prefixes`] and
//! [`FederationDirectory::list_owner_bindings_since`].
//!
//! - **I1570** the family read selects the rows whose FAMILY starts with a
//!   prefix (a `scores` row by its `dimension`, any other row by its
//!   `attestation_type`), oldest serve position first; a prefix is a byte
//!   prefix (case kept), and `%` / `_` are ordinary characters, not `LIKE`
//!   wildcards.
//! - **I1571** pages join without a gap or a repeat, `next_cursor` is `Some`
//!   exactly when another row exists (a full last page says so), and a tie on
//!   `admitted_at` is broken by id: a cursor AT the tied instant resumes
//!   inside the tie, after exactly the id it names.
//! - **I1572** it serves what `list_attestations_since` serves: never a
//!   local-tier row, never a tombstoned row unless the tombstone is void for
//!   it (a person-subject row), never a retired carrier, and never an
//!   unregistered type under enforcement (served under report).
//! - **I1573** malformed input is a refusal, its message led by a stable
//!   token: a page size outside [1, 10000] (`serve_limit_out_of_range`), no
//!   prefix, an empty prefix, more than 64 prefixes (`serve_prefixes_refused`).
//! - **I1574** `high_water`: once nothing remains, it is the stream's head,
//!   past the non-matching rows this read ruled out; a resume from it is
//!   empty, and finds the next matching row. (On postgres the head is
//!   clamped below the commit-safe watermark, so the witness first moves
//!   every held position an hour back: settled.)
//! - **I1575** the owner-binding feed reports each node its rows touch once,
//!   at its last row, with the state folded now: an owner binding at
//!   `federation` is `Announced` with its owner, one at `self` is
//!   `NotAnnounced` and names no owner, and a row about no binding is not in
//!   the feed.
//! - **I1576** removal through the same cursor: after a walk has passed a
//!   binding, its withdrawal arrives past the cursor and says
//!   `NotAnnounced`; a later announcement of a `self`-bound node arrives as
//!   `Announced`.
//! - **I1577** the feed pages on candidate rows with `next_cursor` exactly
//!   when more remain, carries `high_water`, and refuses a page size outside
//!   [1, 500] with `serve_limit_out_of_range`.
//!
//! I1578 is the capsule round trip (`ffi::directory_capsule`); I1579 the
//! sqlite plan (`store::sqlite`).
//!
//! The 61.1 review pass (I1670–I1675; the C lane's I1570–I1579 were full):
//!
//! - **I1670** (D13) the family read's selection is
//!   [`row_type::claim_token`](crate::federation::row_type::claim_token)'s,
//!   row for row, over a stream holding every shape: `scores` rows, a
//!   retyped row carrying a dimension, a `delegates_to` and a `withdraws`
//!   that both carry the ownership dimension. A non-`scores` row is never
//!   selected by its dimension, nor a `scores` row by its type.
//! - **I1671** (R2/H4) postgres: a `high_water` taken while a write that
//!   holds a LOWER serve position is still in flight does not pass it, and a
//!   resume from it finds the row once it commits. Plus the clamp itself
//!   (`read_plan::commit_safe_head`), and the empty stream's origin, as unit
//!   cases.
//! - **I1672** (M5) the owner-binding feed: a node whose fold fails is that
//!   node's `Unresolved` item, in its place; every other node is still
//!   reported.
//! - **I1673** (M1) the Live lifecycle SQL hides a target exactly when the
//!   fold (`precedence::retraction_entitled`) counts the stamped `withdraws`
//!   naming it: for every adverse class of `SUBJECT_WITHDRAWS_CARVE_OUT`, a
//!   cosigned act, a tier-crossing co-scrub, the attester's own scrub, a
//!   cosigned group-plane row and a plain row, under every stamp 1-5 and none.
//! - **I1674** (M5) the feed's owner-binding marker SQL and
//!   `admission::is_owner_binding_envelope` agree over a set of envelopes.
//! - **I1675** (D6) `read_plan::cut_one_past`: more exactly when the
//!   executor returned the row past the page, and a refusal when it returned
//!   two.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::attestation_query::Dialect;
    use crate::federation::read_plan::{SERVE_LIMIT_OUT_OF_RANGE, SERVE_PREFIXES_REFUSED};
    use crate::federation::row_type::{with_enforcement, RowTypeEnforcement};
    use crate::federation::steward_purge::{self as sp, PurgePlane};
    use crate::federation::subject_read_1225_invariants::bodies as n;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        attestation_type, cohort_scope, delegation_scope as ds, identity_type as it, owner_binding,
        AnnouncedOwnerState, OwnerBindingChange, ServePage, ServePosition, ServedAttestation,
    };
    use crate::federation::{Error, FederationDirectory, SignedAttestation};
    use chrono::{DateTime, Utc};

    /// A serve position.
    pub(crate) type Pos = ServePosition;

    /// Raw SQL on the backend under test: the tie, retype and stamp plants,
    /// and the counts the SQL-vs-fold witnesses read.
    #[async_trait::async_trait]
    pub(crate) trait RawSql: Sync {
        /// The attestation table, schema-qualified.
        fn attestations_table(&self) -> &'static str;
        /// The backend's dialect.
        fn dialect(&self) -> Dialect;
        /// Run `sql`.
        async fn exec(&self, sql: &str);
        /// The one integer `sql` selects.
        async fn count(&self, sql: &str) -> i64;
        /// Move every held serve position far enough back that the
        /// backend's commit-safe watermark is past all of them: a no-op where
        /// the head is exact (sqlite).
        async fn settle_every_position(&self);
    }

    #[cfg(feature = "sqlite")]
    #[async_trait::async_trait]
    impl RawSql for crate::store::sqlite::SqliteBackend {
        fn attestations_table(&self) -> &'static str {
            "federation_attestations"
        }
        fn dialect(&self) -> Dialect {
            Dialect::Sqlite
        }
        async fn exec(&self, sql: &str) {
            self.test_execute(sql).await;
        }
        async fn count(&self, sql: &str) -> i64 {
            self.test_count(sql).await
        }
        async fn settle_every_position(&self) {}
    }

    #[cfg(feature = "postgres")]
    #[async_trait::async_trait]
    impl RawSql for crate::store::postgres::PostgresBackend {
        fn attestations_table(&self) -> &'static str {
            "cirislens.federation_attestations"
        }
        fn dialect(&self) -> Dialect {
            Dialect::Postgres
        }
        async fn exec(&self, sql: &str) {
            self.test_execute(sql).await;
        }
        async fn count(&self, sql: &str) -> i64 {
            self.test_count(sql).await
        }
        async fn settle_every_position(&self) {
            self.test_execute(
                "UPDATE cirislens.federation_attestations \
                 SET admitted_at = admitted_at - interval '1 hour'",
            )
            .await;
        }
    }

    /// `e` is an `InvalidArgument` whose message is led by `token`.
    pub(crate) fn refused_with(e: &Error, token: &str, what: &str) {
        match e {
            Error::InvalidArgument(m) => assert!(
                m.starts_with(&format!("{token}: ")),
                "{what}: the refusal is led by {token}: {m}"
            ),
            other => panic!("{what}: expected an InvalidArgument led by {token}, got {other:?}"),
        }
    }

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The attester (an agent) and a subject key, tagged.
    pub(crate) async fn attester(d: &dyn FederationDirectory, tag: &str) -> (String, String) {
        let a = format!("i1570-attester-{tag}");
        ts::register_hybrid_key(d, &a).await;
        (a, format!("i1570-subject-{tag}"))
    }

    /// A served self-report by `a` under `dim`, naming `k`. Its id.
    pub(crate) async fn put_dim(
        d: &dyn FederationDirectory,
        a: &str,
        k: &str,
        dim: &str,
    ) -> String {
        n::put_naming(d, a, &[k], dim, n::at(10), None).await
    }

    /// One page of the family read.
    pub(crate) async fn page(
        d: &dyn FederationDirectory,
        since: Option<Pos>,
        families: &[&str],
        limit: i64,
    ) -> ServePage<ServedAttestation> {
        d.list_attestations_since_by_prefixes(since, &v(families), limit)
            .await
            .expect("served")
    }

    fn ids(p: &ServePage<ServedAttestation>) -> Vec<String> {
        p.items
            .iter()
            .map(|r| r.attestation.attestation_id.clone())
            .collect()
    }

    /// Every page of the family read after `since`, `limit` per page: the
    /// ids in order, each page's (row count, next cursor present), and the
    /// last page's `high_water`.
    pub(crate) async fn walk(
        d: &dyn FederationDirectory,
        since: Option<Pos>,
        families: &[&str],
        limit: i64,
    ) -> (Vec<String>, Vec<(usize, bool)>, Pos) {
        let mut got = Vec::new();
        let mut shape = Vec::new();
        let mut cursor = since;
        loop {
            let p = page(d, cursor.clone(), families, limit).await;
            shape.push((p.items.len(), p.next_cursor.is_some()));
            got.extend(ids(&p));
            if let Some(next) = &p.next_cursor {
                assert_eq!(
                    &p.high_water, next,
                    "while more remain, high_water is next_cursor"
                );
            }
            match p.next_cursor {
                Some(c) => {
                    assert!(shape.len() < 200, "the walk does not end");
                    cursor = Some(c);
                }
                None => return (got, shape, p.high_water),
            }
        }
    }

    /// The serve position of every served row, by id.
    async fn positions(d: &dyn FederationDirectory) -> std::collections::BTreeMap<String, Pos> {
        d.list_attestations_since(None, u32::MAX)
            .await
            .expect("stream")
            .into_iter()
            .map(|r| (r.attestation.attestation_id.clone(), r.serve_position()))
            .collect()
    }

    /// **I1570** — the selection, by byte prefix of the family, OR across the
    /// list.
    pub(crate) async fn i1570_prefixes_select_by_dimension_or_type(
        d: &dyn FederationDirectory,
        raw: &dyn RawSql,
        tag: &str,
    ) {
        let (a, k) = attester(d, tag).await;
        let a1 = put_dim(d, &a, &k, "i1570a:x:v1").await;
        let b1 = put_dim(d, &a, &k, "i1570b:z:v1").await;
        let c1 = put_dim(d, &a, &k, "i1570c:w:v1").await;
        // Case is kept: an upper-case dimension, planted as stored state (the
        // door's own dimension rules are not what this measures), is not
        // under "i1570a:".
        let upper = put_dim(d, &a, &k, "i1570q:x:v1").await;
        raw.exec(&format!(
            "UPDATE {} SET attestation_envelope = \
             replace(attestation_envelope, 'i1570q:x:v1', 'i1570A:x:v1') \
             WHERE attestation_id = '{upper}'",
            raw.attestations_table()
        ))
        .await;
        let a2 = put_dim(d, &a, &k, "i1570a:y:v1").await;
        // A binding: the only `delegates_to` here.
        let (owner, node) = owner_and_node(d, &format!("{tag}-1570")).await;
        let binding = bind(d, &owner, &node, cohort_scope::FEDERATION).await;

        let all = |p: &ServePage<ServedAttestation>| -> Vec<String> { ids(p) };
        assert_eq!(
            all(&page(d, None, &["i1570a:"], 100).await),
            vec![a1.clone(), a2.clone()],
            "I1570 {tag}: one family prefix, serve order"
        );
        assert_eq!(
            all(&page(d, None, &["i1570a:", "i1570b:"], 100).await),
            vec![a1.clone(), b1.clone(), a2.clone()],
            "I1570 {tag}: two prefixes are an OR"
        );
        assert_eq!(
            all(&page(d, None, &["i1570A:"], 100).await),
            vec![upper.clone()],
            "I1570 {tag}: a prefix is case-sensitive"
        );
        assert_eq!(
            all(&page(d, None, &["delegates"], 100).await)
                .into_iter()
                .filter(|id| *id == binding)
                .count(),
            1,
            "I1570 {tag}: a `delegates_to`'s family is its type"
        );
        assert!(
            !all(&page(d, None, &["delegates"], 100).await)
                .iter()
                .any(|id| [&a1, &b1, &c1, &upper, &a2].contains(&id)),
            "I1570 {tag}: a type's prefix selects no `scores` row"
        );
        assert!(
            !all(&page(d, None, &["ownership:"], 100).await).contains(&binding),
            "I1570 {tag}: a `delegates_to` is not selected by the dimension it carries"
        );
        let both = all(&page(d, None, &["i1570c:", "delegates_to"], 100).await);
        assert!(
            both.contains(&c1) && both.contains(&binding) && !both.contains(&a1),
            "I1570 {tag}: a dimension family OR a type family: {both:?}"
        );
        // `LIKE` wildcards are ordinary bytes: under `LIKE 'i1570_%'` every
        // row above would match, under a byte prefix none does.
        for wild in ["i1570_", "i1570%", "i1570_:", "%"] {
            assert!(
                page(d, None, &[wild], 100).await.items.is_empty(),
                "I1570 {tag}: {wild:?} is a literal prefix, not a pattern"
            );
        }
        assert!(
            page(d, None, &["i1570z:"], 100).await.items.is_empty(),
            "I1570 {tag}: a prefix nothing has"
        );
    }

    /// **I1670** — the family read's selection is `row_type::claim_token`'s,
    /// row for row, over every shape the stream holds.
    pub(crate) async fn i1670_the_family_is_claim_tokens(
        d: &dyn FederationDirectory,
        raw: &dyn RawSql,
        tag: &str,
    ) {
        let (a, k) = attester(d, tag).await;
        let scored = put_dim(d, &a, &k, "i1670a:x:v1").await;
        // A row retyped to a type-slot family, still carrying a `dimension`
        // under another family (stored state; the door's type rules are not
        // what this measures).
        let typed = put_dim(d, &a, &k, "i1670a:typed:v1").await;
        raw.exec(&format!(
            "UPDATE {} SET attestation_type = 'i1670t:typed' WHERE attestation_id = '{typed}'",
            raw.attestations_table()
        ))
        .await;
        // A `delegates_to` and a `withdraws` that both carry the ownership
        // dimension: their families are their verbs.
        let (owner, node) = owner_and_node(d, &format!("{tag}-1670")).await;
        let binding = bind(d, &owner, &node, cohort_scope::FEDERATION).await;
        let withdrawn = withdraw(d, &owner, &node, &binding).await;
        let held = d
            .list_attestations_since(None, u32::MAX)
            .await
            .expect("the stream");
        for prefixes in [
            vec!["i1670a:"],
            vec!["i1670t:"],
            vec!["ownership:"],
            vec!["withdraws"],
            vec!["delegates_to", "i1670a:x:"],
            vec!["scores"],
            vec!["i1670"],
        ] {
            let want: Vec<String> = held
                .iter()
                .filter(|r| {
                    crate::federation::row_type::claim_token(&r.attestation)
                        .is_some_and(|t| prefixes.iter().any(|p| t.starts_with(p)))
                })
                .map(|r| r.attestation.attestation_id.clone())
                .collect();
            let (got, _, _) = walk(d, None, &prefixes, 2).await;
            assert_eq!(got, want, "I1670 {tag} {prefixes:?}: claim_token's family");
        }
        // Not vacuous: each shape is selected by its own family and not by
        // the other one it carries.
        let by_dimension = walk(d, None, &["i1670a:"], 100).await.0;
        assert!(
            by_dimension.contains(&scored) && !by_dimension.contains(&typed),
            "I1670 {tag}: a retyped row is not selected by the dimension it carries"
        );
        assert!(
            walk(d, None, &["i1670t:"], 100).await.0.contains(&typed),
            "I1670 {tag}: a retyped row is selected by its type"
        );
        assert!(
            walk(d, None, &["withdraws"], 100)
                .await
                .0
                .contains(&withdrawn),
            "I1670 {tag}: a composer's family is its verb"
        );
        let ownership = walk(d, None, &["ownership:"], 100).await.0;
        assert!(
            !ownership.contains(&withdrawn) && !ownership.contains(&binding),
            "I1670 {tag}: a composer is not selected by its dimension"
        );
        assert!(
            !walk(d, None, &["scores"], 100).await.0.contains(&scored),
            "I1670 {tag}: a `scores` row is not selected by its type"
        );
    }

    /// **I1571** — the cursor, `next_cursor` as "more", and ties.
    pub(crate) async fn i1571_cursor_continuity_and_ties(
        d: &dyn FederationDirectory,
        raw: &dyn RawSql,
        tag: &str,
    ) {
        let (a, k) = attester(d, tag).await;
        let mut want = Vec::new();
        for i in 0..5 {
            want.push(put_dim(d, &a, &k, &format!("i1571:{i}:v1")).await);
        }
        put_dim(d, &a, &k, "i1571x:other:v1").await;
        let dims = ["i1571:"];
        let (all, shape, _) = walk(d, None, &dims, 100).await;
        assert_eq!(all, want, "I1571 {tag}: every row, admission order");
        assert_eq!(shape, vec![(5, false)], "I1571 {tag}");
        for (limit, want_shape) in [
            (2, vec![(2, true), (2, true), (1, false)]),
            (5, vec![(5, false)]),
            (4, vec![(4, true), (1, false)]),
            (
                1,
                vec![(1, true); 4].into_iter().chain([(1, false)]).collect(),
            ),
        ] {
            let (got, shape, _) = walk(d, None, &dims, limit).await;
            assert_eq!(got, all, "I1571 {tag} limit {limit}: no gap, no repeat");
            assert_eq!(
                shape, want_shape,
                "I1571 {tag} limit {limit}: more exactly when another row exists"
            );
        }

        // THE TIE, planted: three rows at one instant, after every other.
        let mut tied = vec![want[1].clone(), want[2].clone(), want[3].clone()];
        tied.sort();
        let t = DateTime::<Utc>::from_timestamp(Utc::now().timestamp() + 3_600, 0).expect("t");
        raw.exec(&format!(
            "UPDATE {} SET admitted_at = '{}' WHERE attestation_id IN ('{}', '{}', '{}')",
            raw.attestations_table(),
            t.to_rfc3339(),
            tied[0],
            tied[1],
            tied[2]
        ))
        .await;
        let (got, _, _) = walk(d, None, &dims, 100).await;
        let mut expect = vec![want[0].clone(), want[4].clone()];
        expect.extend(tied.iter().cloned());
        assert_eq!(
            got, expect,
            "I1571 {tag}: the tie sorts after the rest, by id ascending"
        );
        for limit in [1, 2] {
            let (paged, _, _) = walk(d, None, &dims, limit).await;
            assert_eq!(
                paged, expect,
                "I1571 {tag} limit {limit}: a tie larger than the page pages exactly once"
            );
        }
        // A cursor AT the instant: the id decides.
        let at = |id: &str| Some(ServePosition::new(t, id));
        assert_eq!(
            ids(&page(d, at(""), &dims, 100).await),
            tied,
            "I1571 {tag}: an id below the tie resumes before all of it"
        );
        assert_eq!(
            ids(&page(d, at(&tied[0]), &dims, 100).await),
            tied[1..].to_vec(),
            "I1571 {tag}: the cursor's own id is excluded, the rest of the tie kept"
        );
        assert!(
            page(d, at(&tied[2]), &dims, 100).await.items.is_empty(),
            "I1571 {tag}: past the last of the tie, nothing"
        );
    }

    /// **I1572** — the serve rule is `list_attestations_since`'s.
    pub(crate) async fn i1572_serves_what_the_stream_serves(
        d: &dyn FederationDirectory,
        raw: &dyn RawSql,
        tag: &str,
    ) {
        let (a, k) = attester(d, tag).await;
        let person = format!("i1572-person-{tag}");
        ts::register_hybrid_key_as(d, &person, &person, it::USER).await;
        // v61.1.0 (review D13) — the read matches by FAMILY (a `scores` row's
        // dimension, any other row's type), so the two retyped rows below
        // keep their type inside a family the read asks for: otherwise their
        // exclusion would be the family's, not the serve filter's, and the
        // legs would pass vacuously.
        let dims = ["i1572:", "holds_bytes:sha256:5a5a5a5a"];
        let kept = put_dim(d, &a, &k, "i1572:k:v1").await;
        let doomed = put_dim(d, &a, &k, "i1572:d:v1").await;
        // Names a PERSON: a tombstone is void for it.
        let void = n::put_naming(d, &a, &[&k, &person], "i1572:p:v1", n::at(10), None).await;
        let unregistered = put_dim(d, &a, &k, "i1572:u:v1").await;
        let retired = put_dim(d, &a, &k, "i1572:r:v1").await;
        d.attestation_insert_local(crate::federation::types::LocalAttestationInput {
            attestation_id: None,
            attesting_key_id: a.clone(),
            attested_key_id: None,
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            expires_at: None,
            attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                serde_json::json!({ "dimension": "i1572:l:v1", "n": "local" }),
            )
            .expect("object"),
            subject_key_ids: vec![k.clone()],
            cohort_scope: cohort_scope::SELF.to_owned(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        })
        .await
        .expect("I1572 the local row is written");
        let table = raw.attestations_table();
        raw.exec(&format!(
            "UPDATE {table} SET attestation_type = 'i1572:x:unregistered' \
             WHERE attestation_id = '{unregistered}'"
        ))
        .await;
        raw.exec(&format!(
            "UPDATE {table} SET attestation_type = 'holds_bytes:sha256:5a5a5a5a' \
             WHERE attestation_id = '{retired}'"
        ))
        .await;

        let report = with_enforcement(RowTypeEnforcement::Report, async {
            walk(d, None, &dims, 100).await.0
        })
        .await;
        assert_eq!(
            report,
            vec![
                kept.clone(),
                doomed.clone(),
                void.clone(),
                unregistered.clone()
            ],
            "I1572 {tag}: under report an unregistered type is served; never the local row, \
             never a retired carrier"
        );
        let enforce = with_enforcement(RowTypeEnforcement::Enforce, async {
            walk(d, None, &dims, 100).await.0
        })
        .await;
        assert_eq!(
            enforce,
            vec![kept.clone(), doomed.clone(), void.clone()],
            "I1572 {tag}: under enforcement an unregistered type is not served (CC 2.4)"
        );

        let t = Utc::now();
        let notice_id = {
            use sha2::Digest as _;
            hex::encode(sha2::Sha256::digest(format!("i1572-{tag}").as_bytes()))
        };
        let exec = sp::PurgeExecution {
            notice_id: notice_id.clone(),
            selection_digest: "ab".repeat(32),
            claimant_key_id: "moderator-1".to_owned(),
            legal_basis: "ncmec_csam".to_owned(),
            record_count: 2,
            notice_jcs: "{}".to_owned(),
            cosignatures_json: "[]".to_owned(),
            executed_by: "node-i1572".to_owned(),
            origin: sp::origin::LOCAL.to_owned(),
            executed_at: t,
            admitted_at: t,
            finalized_at: None,
        };
        let stones: Vec<sp::PurgeTombstone> = [&doomed, &void]
            .iter()
            .enumerate()
            .map(|(i, id)| sp::PurgeTombstone {
                notice_id: notice_id.clone(),
                ordinal: i as u64,
                plane: PurgePlane::Attestation,
                record_ref: (*id).clone(),
                derived_from: None,
            })
            .collect();
        d.purge_put_execution(&exec, &stones)
            .await
            .expect("I1572 tombstones recorded");
        let after = with_enforcement(RowTypeEnforcement::Report, async {
            walk(d, None, &dims, 100).await.0
        })
        .await;
        assert_eq!(
            after,
            vec![kept, void, unregistered],
            "I1572 {tag}: a tombstoned row is not served; the person-subject row is"
        );
    }

    /// **I1573** — malformed input is a refusal, never an empty page, and
    /// each refusal is led by its stable token.
    pub(crate) async fn i1573_malformed_input_is_refused(d: &dyn FederationDirectory, tag: &str) {
        let (a, k) = attester(d, tag).await;
        put_dim(d, &a, &k, "i1573:x:v1").await;
        let one = v(&["i1573:"]);
        for bad in [0, -1, 10_001] {
            let e = d
                .list_attestations_since_by_prefixes(None, &one, bad)
                .await
                .expect_err("I1573: a page outside [1, 10000] is refused");
            refused_with(&e, SERVE_LIMIT_OUT_OF_RANGE, "I1573 limit");
        }
        d.list_attestations_since_by_prefixes(None, &one, 10_000)
            .await
            .expect("I1573: a page of 10000 is served");
        for (bad, what) in [
            (Vec::new(), "no prefix at all"),
            (v(&[""]), "an empty prefix"),
            (v(&["i1573:", ""]), "an empty prefix among others"),
            (
                (0..65).map(|i| format!("i1573:{i}:")).collect(),
                "65 prefixes",
            ),
        ] {
            let e = d
                .list_attestations_since_by_prefixes(None, &bad, 10)
                .await
                .expect_err("I1573: refused");
            refused_with(&e, SERVE_PREFIXES_REFUSED, &format!("I1573 {what}"));
        }
        let many: Vec<String> = (0..64).map(|i| format!("i1573:{i}:")).collect();
        let page = d
            .list_attestations_since_by_prefixes(None, &many, 10)
            .await
            .expect("I1573: 64 prefixes is served");
        assert!(page.items.is_empty(), "I1573 {tag}");
    }

    /// **I1574** — `high_water` is the head once nothing remains.
    pub(crate) async fn i1574_high_water_passes_ruled_out_rows(
        d: &dyn FederationDirectory,
        raw: &dyn RawSql,
        tag: &str,
    ) {
        let (a, k) = attester(d, tag).await;
        let dims = ["i1574:"];
        let first = put_dim(d, &a, &k, "i1574:a:v1").await;
        let mut others = Vec::new();
        for i in 0..3 {
            others.push(put_dim(d, &a, &k, &format!("i1574x:{i}:v1")).await);
        }
        // Past postgres's commit-safe watermark (I1671 is the clamp itself).
        raw.settle_every_position().await;
        let pos = positions(d).await;
        let head = pos.values().max().cloned().expect("the stream holds rows");
        assert_eq!(
            Some(&head),
            pos.get(others.last().expect("rows")),
            "I1574 {tag}: the last row put is the head"
        );
        let p = page(d, None, &dims, 100).await;
        assert_eq!(ids(&p), vec![first.clone()], "I1574 {tag}");
        assert!(p.next_cursor.is_none(), "I1574 {tag}: nothing remains");
        assert_eq!(
            p.high_water, head,
            "I1574 {tag}: high_water is the head, past the rows ruled out"
        );
        assert!(
            Some(&p.high_water) > pos.get(&first),
            "I1574 {tag}: high_water is beyond the last match"
        );
        let resumed = page(d, Some(p.high_water.clone()), &dims, 100).await;
        assert!(resumed.items.is_empty(), "I1574 {tag}: nothing new");
        assert_eq!(
            resumed.high_water, p.high_water,
            "I1574 {tag}: an idle resume stays where it was"
        );
        let second = put_dim(d, &a, &k, "i1574:b:v1").await;
        let found = page(d, Some(p.high_water.clone()), &dims, 100).await;
        assert_eq!(
            ids(&found),
            vec![second],
            "I1574 {tag}: a resume from high_water finds the next match"
        );
    }

    // ── #1163 ────────────────────────────────────────────────────────────

    /// A `user` owner and a node key, tagged.
    pub(crate) async fn owner_and_node(d: &dyn FederationDirectory, tag: &str) -> (String, String) {
        let owner = format!("o1575-{tag}");
        let node = format!("n1575-{tag}");
        ts::register_user_role_key(d, &owner).await;
        ts::register_hybrid_key(d, &node).await;
        (owner, node)
    }

    /// `owner`'s owner binding of `node` at `scope`, put through the door. Its id.
    pub(crate) async fn bind(
        d: &dyn FederationDirectory,
        owner: &str,
        node: &str,
        scope: &str,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let mut row = ts::bare_attestation(
            &id,
            owner,
            node,
            &serde_json::json!({
                "id": id,
                "kind": "delegates_to",
                "dimension": owner_binding::DIMENSION,
                "delegation_purpose": owner_binding::PURPOSE,
                "scope": [ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
            }),
        );
        row.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        row.cohort_scope = scope.to_owned();
        ts::seal_row_in_place(owner, &mut row);
        d.put_attestation(SignedAttestation { attestation: row })
            .await
            .unwrap_or_else(|e| panic!("I1575 fixture: {owner} binds {node} at {scope}: {e}"));
        id
    }

    /// `owner` withdraws its binding `binding_id` of `node`. Its id.
    pub(crate) async fn withdraw(
        d: &dyn FederationDirectory,
        owner: &str,
        node: &str,
        binding_id: &str,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let mut w = ts::bare_attestation(
            &id,
            owner,
            node,
            &serde_json::json!({
                "dimension": owner_binding::DIMENSION,
                "references_attestation_id": binding_id,
                "withdrawal_reason": "the owner withdraws the announcement",
            }),
        );
        w.attestation_type = attestation_type::WITHDRAWS.to_owned();
        let w = ts::seal_row(owner, w);
        d.put_attestation(SignedAttestation { attestation: w })
            .await
            .expect("I1576 the owner withdraws its binding");
        id
    }

    /// Every page of the feed after `since`, `limit` rows per page: the
    /// items, each page's (item count, more), and the last `high_water`.
    pub(crate) async fn feed(
        d: &dyn FederationDirectory,
        since: Option<Pos>,
        limit: i64,
    ) -> (Vec<OwnerBindingChange>, Vec<(usize, bool)>, Pos) {
        let mut items = Vec::new();
        let mut shape = Vec::new();
        let mut cursor = since;
        loop {
            let p = d
                .list_owner_bindings_since(cursor.clone(), limit)
                .await
                .expect("the feed is served");
            shape.push((p.items.len(), p.next_cursor.is_some()));
            items.extend(p.items);
            match p.next_cursor {
                Some(c) => {
                    assert!(shape.len() < 200, "the feed walk does not end");
                    assert_eq!(p.high_water, c);
                    cursor = Some(c);
                }
                None => return (items, shape, p.high_water),
            }
        }
    }

    fn of<'a>(items: &'a [OwnerBindingChange], node: &str) -> Vec<&'a OwnerBindingChange> {
        items.iter().filter(|c| c.node_key_id == node).collect()
    }

    /// **I1575** — what the feed reports, and once per node per page.
    pub(crate) async fn i1575_feed_reports_each_node_its_state_now(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (o1, n1) = owner_and_node(d, &format!("{tag}a")).await;
        let (o2, n2) = owner_and_node(d, &format!("{tag}b")).await;
        let first = bind(d, &o1, &n1, cohort_scope::FEDERATION).await;
        let private = bind(d, &o2, &n2, cohort_scope::SELF).await;
        // A refresh by the same owner: N1's last row in the page.
        let refresh = bind(d, &o1, &n1, cohort_scope::FEDERATION).await;
        // A `scores` row naming N1: not a candidate row.
        let (a, _) = attester(d, tag).await;
        let unrelated = put_dim(d, &a, &n1, "i1575:s:v1").await;

        let p = d
            .list_owner_bindings_since(None, 100)
            .await
            .expect("I1575 served");
        let mine: Vec<&OwnerBindingChange> = p
            .items
            .iter()
            .filter(|c| c.node_key_id == n1 || c.node_key_id == n2)
            .collect();
        assert_eq!(
            mine.iter()
                .map(|c| c.node_key_id.as_str())
                .collect::<Vec<_>>(),
            vec![n2.as_str(), n1.as_str()],
            "I1575 {tag}: one item per node, ordered by its last row"
        );
        assert_eq!(
            mine[1].state,
            AnnouncedOwnerState::Announced {
                owner_key_id: o1.clone()
            },
            "I1575 {tag}: a live binding at federation is announced, with its owner"
        );
        assert_eq!(
            mine[1].position.attestation_id, refresh,
            "I1575 {tag}: the node is reported at its last row"
        );
        assert_ne!(mine[1].position.attestation_id, first, "I1575 {tag}");
        assert_eq!(
            mine[0].state,
            AnnouncedOwnerState::NotAnnounced,
            "I1575 {tag}: a binding at self is owned, not announced, and names no owner"
        );
        assert_eq!(mine[0].position.attestation_id, private, "I1575 {tag}");
        assert!(
            p.items
                .iter()
                .all(|c| c.position.attestation_id != unrelated),
            "I1575 {tag}: a scores row is not a candidate"
        );
        assert!(
            p.next_cursor.is_none() && !p.high_water.is_origin(),
            "I1575 {tag}"
        );
    }

    /// **I1576** — a binding stopping being live is observable through the
    /// same cursor.
    pub(crate) async fn i1576_removal_arrives_through_the_cursor(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (o1, n1) = owner_and_node(d, &format!("{tag}a")).await;
        let (o2, n2) = owner_and_node(d, &format!("{tag}b")).await;
        let live = bind(d, &o1, &n1, cohort_scope::FEDERATION).await;
        bind(d, &o2, &n2, cohort_scope::SELF).await;
        let (seen, _, cursor) = feed(d, None, 2).await;
        assert_eq!(
            of(&seen, &n1).last().map(|c| c.state.clone()),
            Some(AnnouncedOwnerState::Announced {
                owner_key_id: o1.clone()
            }),
            "I1576 {tag}: the walk saw N1 announced"
        );
        assert_eq!(
            of(&seen, &n2).last().map(|c| c.state.clone()),
            Some(AnnouncedOwnerState::NotAnnounced),
            "I1576 {tag}: the walk saw N2 not announced"
        );
        assert!(!cursor.is_origin(), "I1576 {tag}: a cursor past the walk");
        let (idle, _, again) = feed(d, Some(cursor.clone()), 2).await;
        assert!(idle.is_empty(), "I1576 {tag}: nothing past the walk");
        assert_eq!(again, cursor, "I1576 {tag}");

        // The owner withdraws N1's binding; O2 announces N2.
        let w = withdraw(d, &o1, &n1, &live).await;
        let announce = bind(d, &o2, &n2, cohort_scope::FEDERATION).await;
        let (changed, _, _) = feed(d, Some(cursor), 100).await;
        assert_eq!(
            changed
                .iter()
                .map(|c| {
                    (
                        c.node_key_id.clone(),
                        c.state.clone(),
                        c.position.attestation_id.clone(),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (n1.clone(), AnnouncedOwnerState::NotAnnounced, w),
                (
                    n2.clone(),
                    AnnouncedOwnerState::Announced {
                        owner_key_id: o2.clone()
                    },
                    announce
                ),
            ],
            "I1576 {tag}: the withdrawal arrives past the cursor as not announced, and the \
             announcement as announced"
        );
        assert_eq!(
            crate::federation::admission::announced_owner_state(d, &n1)
                .await
                .expect("fold"),
            AnnouncedOwnerState::NotAnnounced,
            "I1576 {tag}: the feed's state is the fold's"
        );
    }

    /// **I1577** — the feed's paging and bound.
    pub(crate) async fn i1577_feed_pages_and_refuses(d: &dyn FederationDirectory, tag: &str) {
        let mut nodes = Vec::new();
        for i in 0..3 {
            let (o, nd) = owner_and_node(d, &format!("{tag}{i}")).await;
            bind(d, &o, &nd, cohort_scope::FEDERATION).await;
            nodes.push(nd);
        }
        let (all, _, _) = feed(d, None, 100).await;
        let order: Vec<String> = all
            .iter()
            .filter(|c| nodes.contains(&c.node_key_id))
            .map(|c| c.node_key_id.clone())
            .collect();
        assert_eq!(order, nodes, "I1577 {tag}: serve order");
        let total = all.len();
        let (one, shape, high) = feed(d, None, 1).await;
        assert_eq!(
            one.iter().map(|c| &c.node_key_id).collect::<Vec<_>>(),
            all.iter().map(|c| &c.node_key_id).collect::<Vec<_>>(),
            "I1577 {tag}: one candidate row per page, nothing lost"
        );
        assert_eq!(shape.len(), total, "I1577 {tag}");
        assert_eq!(
            shape.last(),
            Some(&(1, false)),
            "I1577 {tag}: the last page says so"
        );
        assert!(
            shape[..total - 1].iter().all(|s| *s == (1, true)),
            "I1577 {tag}: {shape:?}"
        );
        assert!(!high.is_origin(), "I1577 {tag}: high_water");
        // v61.1.0 (#1163 review M5) — each node is a fold: the page is at
        // most 500.
        for bad in [0, -1, 501, 10_000] {
            let e = d
                .list_owner_bindings_since(None, bad)
                .await
                .expect_err("I1577: a page outside [1, 500] is refused");
            refused_with(&e, SERVE_LIMIT_OUT_OF_RANGE, "I1577 limit");
        }
        d.list_owner_bindings_since(None, 500)
            .await
            .expect("I1577: a page of 500 is served");
    }

    // ── the 61.1 review pass ─────────────────────────────────────────────

    /// **I1671** (postgres) — a `high_water` read while a write holding a
    /// LOWER serve position is still in flight does not pass it. `pause` is
    /// armed at `delegation_cycle_before_insert` on `d`: the `delegates_to`
    /// below takes its serve position, opens its transaction and waits there
    /// while a later row commits ABOVE it and the family read runs.
    pub(crate) async fn i1671_high_water_waits_for_a_write_in_flight(
        d: &dyn FederationDirectory,
        pause: std::sync::Arc<crate::store::test_hooks::Pause>,
        tag: &str,
    ) {
        let (a, k) = attester(d, tag).await;
        let (granter, grantee) = (format!("i1671-g-{tag}"), format!("i1671-e-{tag}"));
        ts::register_hybrid_key_as(d, &granter, &granter, it::AGENT).await;
        ts::register_hybrid_key_as(d, &grantee, &grantee, it::AGENT).await;
        let families = ["i1671:", attestation_type::DELEGATES_TO];
        let old = put_dim(d, &a, &k, "i1671:old:v1").await;
        let (held, during) =
            tokio::join!(ts::put_delegates_to(d, &granter, &grantee, None), async {
                pause.reached().await;
                // Assigned after the held row's position, committed before it.
                put_dim(d, &a, &k, "i1671x:later:v1").await;
                let p = page(d, None, &families, 100).await;
                pause.resume();
                p
            },);
        let held = held.expect("I1671: the held delegation commits once resumed");
        assert_eq!(
            ids(&during),
            vec![old.clone()],
            "I1671 {tag}: only the committed match is served"
        );
        assert!(during.next_cursor.is_none(), "I1671 {tag}");
        let pos = positions(d).await;
        let held_at = pos.get(&held).expect("I1671: the held row is served");
        assert!(
            &during.high_water < held_at,
            "I1671 {tag}: high_water {:?} passed the row in flight at {held_at:?}",
            during.high_water
        );
        let resumed = page(d, Some(during.high_water.clone()), &families, 100).await;
        assert!(
            ids(&resumed).contains(&held),
            "I1671 {tag}: a resume from high_water finds the row that committed late"
        );
    }

    /// The Live lifecycle predicate over `fa`, with its composer types
    /// inlined (the count reads take no binds).
    fn live_predicate(dialect: Dialect) -> String {
        let (mut sql, types) = crate::federation::attestation_query::lifecycle_predicate(
            crate::read::LifecycleView::Live,
            dialect,
            "fa",
            1,
        )
        .expect("Live hides composers");
        for (i, t) in types.iter().enumerate().rev() {
            let ph = match dialect {
                Dialect::Sqlite => format!("?{}", i + 1),
                Dialect::Postgres => format!("${}", i + 1),
            };
            sql = sql.replace(&ph, &format!("'{t}'"));
        }
        sql
    }

    /// **I1673** — the Live SQL hides a target exactly when the fold counts
    /// the stamped `withdraws` naming it.
    pub(crate) async fn i1673_live_sql_agrees_with_the_fold_on_stamps(
        d: &dyn FederationDirectory,
        raw: &dyn RawSql,
        tag: &str,
    ) {
        use crate::federation::admission::SUBJECT_WITHDRAWS_CARVE_OUT;
        let (a, k) = attester(d, tag).await;
        // Registered: the attester column references a held key.
        let stranger = format!("i1673-stranger-{tag}");
        ts::register_hybrid_key(d, &stranger).await;
        let scrub = |key: &str, cosigned_at: Option<&str>| {
            let mut s = serde_json::json!({
                "scrub_key_id": key,
                "scrub_signature_classical": "c2ln",
            });
            if let Some(at) = cosigned_at {
                s["cosigned_at"] = serde_json::json!(at);
            }
            serde_json::json!([s]).to_string()
        };
        let cosigned = scrub("i1673-cosigner", None);
        // (what, the target's dimension, its additional_scrubs, carved out)
        let mut cases: Vec<(String, String, String, bool)> = SUBJECT_WITHDRAWS_CARVE_OUT
            .iter()
            .map(|p| {
                (
                    format!("adverse {p}"),
                    format!("{p}i1673:v1"),
                    "[]".to_owned(),
                    true,
                )
            })
            .collect();
        cases.extend([
            (
                "plain".to_owned(),
                "i1673:plain:v1".to_owned(),
                "[]".to_owned(),
                false,
            ),
            (
                "cosigned act".to_owned(),
                "i1673:cosigned:v1".to_owned(),
                cosigned.clone(),
                true,
            ),
            (
                "adverse and cosigned".to_owned(),
                "capacity:i1673b:v1".to_owned(),
                cosigned.clone(),
                true,
            ),
            (
                "tier-crossing co-scrub".to_owned(),
                "i1673:coscrub:v1".to_owned(),
                scrub("i1673-node", Some("2026-01-01T00:00:00.000Z")),
                false,
            ),
            (
                "the attester's own scrub".to_owned(),
                "i1673:own:v1".to_owned(),
                scrub(&a, None),
                false,
            ),
            (
                "a cosigned group-plane row".to_owned(),
                crate::federation::group_plane::GROUP_ROSTER_DIMENSION.to_owned(),
                cosigned,
                false,
            ),
        ]);
        let table = raw.attestations_table();
        let live = live_predicate(raw.dialect());
        for (i, (what, dimension, scrubs, carved)) in cases.iter().enumerate() {
            let seed = format!("i1673:seed{i}:v1");
            let target = put_dim(d, &a, &k, &seed).await;
            // The producer's own withdrawal, admitted while the target is
            // plain; re-signed below as a stranger's, as stored state.
            let wid = uuid::Uuid::new_v4().to_string();
            let mut w = ts::bare_attestation(
                &wid,
                &a,
                &a,
                &serde_json::json!({
                    "references_attestation_id": target,
                    "withdrawal_reason": "i1673",
                }),
            );
            w.attestation_type = attestation_type::WITHDRAWS.to_owned();
            let w = ts::seal_row(&a, w);
            d.put_attestation(SignedAttestation { attestation: w })
                .await
                .unwrap_or_else(|e| panic!("I1673 {what}: the producer withdraws: {e}"));
            raw.exec(&format!(
                "UPDATE {table} SET attestation_envelope = \
                 replace(attestation_envelope, '{seed}', '{dimension}'), \
                 additional_scrubs = '{scrubs}' WHERE attestation_id = '{target}'"
            ))
            .await;
            for rule in [None, Some(1), Some(2), Some(3), Some(4), Some(5)] {
                raw.exec(&format!(
                    "UPDATE {table} SET attesting_key_id = '{stranger}', \
                     withdraws_admission_rule = {} WHERE attestation_id = '{wid}'",
                    rule.map_or_else(|| "NULL".to_owned(), |r: i32| r.to_string())
                ))
                .await;
                let t_row = d
                    .get_attestation(&target)
                    .await
                    .expect("read")
                    .expect("the target is held");
                let w_row = d
                    .get_attestation(&wid)
                    .await
                    .expect("read")
                    .expect("the withdrawal is held");
                assert_eq!(
                    crate::federation::precedence::subject_withdraws_carved_out(&t_row)
                        && !crate::federation::group_plane::is_group_plane_row(&t_row),
                    *carved,
                    "I1673 {what}: the planted target's carve-out"
                );
                let fold = crate::federation::precedence::retraction_entitled(&w_row, &t_row);
                let hidden = raw
                    .count(&format!(
                        "SELECT COUNT(*) FROM {table} fa \
                         WHERE fa.attestation_id = '{target}' AND {live}"
                    ))
                    .await
                    == 0;
                assert_eq!(
                    hidden, fold,
                    "I1673 {tag} {what}, stamp {rule:?}: the Live SQL hides the target exactly \
                     when the fold counts the withdrawal"
                );
                // Not vacuous: the stamp's verdict is the rule's.
                let want = match rule {
                    None => false,
                    Some(1 | 5) => true,
                    Some(_) => !carved,
                };
                assert_eq!(fold, want, "I1673 {tag} {what}, stamp {rule:?}: the fold");
            }
        }
    }

    /// **I1674** — the feed's owner-binding marker SQL and
    /// `admission::is_owner_binding_envelope` agree.
    pub(crate) async fn i1674_owner_binding_marker_agrees(
        d: &dyn FederationDirectory,
        raw: &dyn RawSql,
        tag: &str,
    ) {
        use serde_json::json;
        let (a, k) = attester(d, tag).await;
        let id = put_dim(d, &a, &k, "i1674:x:v1").await;
        let table = raw.attestations_table();
        let marker = crate::federation::read_plan::owner_binding_marker_sql(raw.dialect(), "fa");
        let dim = owner_binding::DIMENSION;
        let purpose = owner_binding::CC_DELEGATION_PURPOSE;
        let mut agreed = (0, 0);
        for envelope in [
            json!({ "dimension": dim }),
            json!({ "delegation_purpose": purpose }),
            json!({ "dimension": dim, "delegation_purpose": owner_binding::PURPOSE }),
            json!({ "delegation_purpose": owner_binding::PURPOSE }),
            json!({ "dimension": "ownership:responsible_party:node:v2" }),
            json!({ "delegation_purpose": "Owner_binding" }),
            json!({ "delegation_purpose": [purpose] }),
            json!({ "delegation_purpose": { "v": purpose } }),
            json!({ "dimension": { "v": dim } }),
            json!({ "nested": { "delegation_purpose": purpose } }),
            json!({}),
        ] {
            let text = envelope.to_string().replace('\'', "''");
            raw.exec(&format!(
                "UPDATE {table} SET attestation_envelope = '{text}' WHERE attestation_id = '{id}'"
            ))
            .await;
            let sql = raw
                .count(&format!(
                    "SELECT COUNT(*) FROM {table} fa WHERE fa.attestation_id = '{id}' AND {marker}"
                ))
                .await
                == 1;
            let rust = crate::federation::admission::is_owner_binding_envelope(&envelope);
            assert_eq!(sql, rust, "I1674 {tag}: {envelope}");
            if rust {
                agreed.0 += 1;
            } else {
                agreed.1 += 1;
            }
        }
        assert_eq!(agreed, (3, 8), "I1674 {tag}: both answers were exercised");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    /// The two backend runners of one witness. `$call` names `$b` (the
    /// backend) and `$t` (the tag).
    macro_rules! backends {
        ($name:ident, |$b:ident, $t:ident| $call:expr) => {
            mod $name {
                use super::*;

                #[cfg(feature = "sqlite")]
                #[tokio::test(flavor = "multi_thread")]
                async fn sqlite() {
                    use crate::store::Backend as _;
                    let backend = crate::store::sqlite::SqliteBackend::open_in_memory()
                        .await
                        .unwrap();
                    backend.run_migrations().await.unwrap();
                    let $b = &backend;
                    let $t = &tag("s");
                    $call.await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test(flavor = "multi_thread")]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        eprintln!(
                            "1163/1190 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED"
                        );
                        return;
                    };
                    let backend = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    backend.run_migrations().await.unwrap();
                    let $b = &backend;
                    let $t = &tag("p");
                    $call.await;
                    eprintln!("{}: RAN", stringify!($name));
                }
            }
        };
    }

    macro_rules! on_every_backend {
        ($name:ident, raw $body:path) => {
            backends!($name, |bk, tg| $body(bk, bk, tg));
        };
        ($name:ident, $body:path) => {
            backends!($name, |bk, tg| $body(bk, tg));
        };
    }

    on_every_backend!(i1570, raw bodies::i1570_prefixes_select_by_dimension_or_type);
    on_every_backend!(i1571, raw bodies::i1571_cursor_continuity_and_ties);
    on_every_backend!(i1572, raw bodies::i1572_serves_what_the_stream_serves);
    on_every_backend!(i1573, bodies::i1573_malformed_input_is_refused);
    on_every_backend!(i1574, raw bodies::i1574_high_water_passes_ruled_out_rows);
    on_every_backend!(i1575, bodies::i1575_feed_reports_each_node_its_state_now);
    on_every_backend!(i1576, bodies::i1576_removal_arrives_through_the_cursor);
    on_every_backend!(i1577, bodies::i1577_feed_pages_and_refuses);
    on_every_backend!(i1670, raw bodies::i1670_the_family_is_claim_tokens);
    on_every_backend!(i1673, raw bodies::i1673_live_sql_agrees_with_the_fold_on_stamps);
    on_every_backend!(i1674, raw bodies::i1674_owner_binding_marker_agrees);

    /// **I1671** on postgres: a write in flight. (sqlite needs none: its one
    /// writer assigns the position inside the write transaction, so the
    /// second write here would wait behind the held one.)
    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1671_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("I1671 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let backend = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        backend.run_migrations().await.unwrap();
        let pause = backend
            .test_hooks()
            .arm_pause("delegation_cycle_before_insert");
        bodies::i1671_high_water_waits_for_a_write_in_flight(&backend, pause, &tag("p")).await;
        eprintln!("i1671_postgres: RAN");
    }
}

/// The plan-level cases of the review pass: no backend run, but the plan
/// module itself exists only with a backend feature.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod plan_units {
    use crate::federation::attestation_query::Dialect;
    use crate::federation::read_plan::{
        commit_safe_head, cut_one_past, cut_serve_page, owner_binding_items, serve_settled_before,
        PG_SERVE_COMMIT_LAG_SECS,
    };
    use crate::federation::types::{AnnouncedOwnerState, ServePosition, ServedAttestation};
    use crate::federation::Error;
    use chrono::{DateTime, TimeDelta, Utc};

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_800_000_000 + secs, 0).expect("t")
    }

    fn served(id: &str, node: &str, secs: i64) -> ServedAttestation {
        let mut row = crate::federation::tier_ingest::test_support::bare_attestation(
            id,
            "i1672-attester",
            node,
            &serde_json::json!({ "n": id }),
        );
        row.attested_key_id = node.to_owned();
        ServedAttestation {
            attestation: row,
            admitted_at: at(secs),
        }
    }

    /// **I1671** (the clamp) — postgres's watermark is the read clock less
    /// the lag, sqlite has none; a head at or past the watermark is clamped
    /// to the watermark with no id, a head below it is kept.
    #[test]
    fn i1671_the_head_is_clamped_below_the_watermark() {
        let now = at(1_000);
        let w = now - TimeDelta::seconds(PG_SERVE_COMMIT_LAG_SECS);
        assert_eq!(serve_settled_before(Dialect::Sqlite, now), None);
        assert_eq!(serve_settled_before(Dialect::Postgres, now), Some(w));
        let below = ServePosition::new(w - TimeDelta::seconds(1), "zz");
        let past = ServePosition::new(now, "aa");
        assert_eq!(commit_safe_head(Some(below.clone()), Some(w)), Some(below));
        assert_eq!(
            commit_safe_head(Some(past.clone()), Some(w)),
            Some(ServePosition::new(w, ""))
        );
        assert_eq!(
            commit_safe_head(Some(ServePosition::new(w, "aa")), Some(w)),
            Some(ServePosition::new(w, "")),
            "a head AT the watermark is not yet settled"
        );
        assert_eq!(commit_safe_head(Some(past.clone()), None), Some(past));
        assert_eq!(commit_safe_head(None, Some(w)), None);
    }

    /// **I1671** (the cut) — with nothing past the page, `high_water` is the
    /// furthest of `since`, the last row and the CLAMPED head; the empty
    /// stream's is the origin, and the origin resumes from the start.
    #[test]
    fn i1671_high_water_takes_the_clamped_head() {
        let door = "i1671";
        let w = at(500);
        let mut rows = vec![served("r1", "n", 100)];
        let head = Some(ServePosition::new(at(900), "head"));
        let (next, high) =
            cut_serve_page(&mut rows, 10, None, head.clone(), Some(w), door).expect("cut");
        assert_eq!(next, None);
        assert_eq!(high, ServePosition::new(w, ""), "the clamped head");
        let (_, exact) =
            cut_serve_page(&mut rows, 10, None, head.clone(), None, door).expect("cut");
        assert_eq!(
            exact,
            ServePosition::new(at(900), "head"),
            "sqlite: the head"
        );
        let mut later = vec![served("r2", "n", 700)];
        let (_, high) = cut_serve_page(&mut later, 10, None, head, Some(w), door).expect("cut");
        assert_eq!(high, later[0].serve_position(), "a row past the watermark");
        let (_, empty) = cut_serve_page(&mut Vec::new(), 10, None, None, None, door).expect("cut");
        assert_eq!(empty, ServePosition::origin());
        assert!(empty.is_origin());
        assert_eq!(ServePosition::resume_after(Some(&empty)), None);
        let since = ServePosition::new(at(1), "x");
        assert_eq!(
            ServePosition::resume_after(Some(&since)),
            Some((at(1), "x".to_owned()))
        );
        let mut two = vec![served("a", "n", 1), served("b", "n", 2)];
        let (next, high) = cut_serve_page(&mut two, 1, None, None, None, door).expect("cut");
        assert_eq!(next, Some(ServePosition::new(at(1), "a")));
        assert_eq!(
            high,
            ServePosition::new(at(1), "a"),
            "more remain: the cursor"
        );
    }

    /// **I1672** — one node whose fold fails is that node's `Unresolved`
    /// item, in its place; every other node is still reported.
    #[tokio::test]
    async fn i1672_a_failed_fold_is_an_item_not_a_failed_page() {
        let rows = vec![
            served("r1", "n1", 1),
            served("r2", "n-bad", 2),
            served("r3", "n2", 3),
            served("r4", "n1", 4),
        ];
        let items = owner_binding_items(&rows, |node| {
            let bad = node == "n-bad";
            async move {
                if bad {
                    Err(Error::Backend("i1672 injected fold failure".into()))
                } else {
                    Ok(AnnouncedOwnerState::NotAnnounced)
                }
            }
        })
        .await;
        let got: Vec<(&str, &str)> = items
            .iter()
            .map(|c| (c.node_key_id.as_str(), c.position.attestation_id.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![("n-bad", "r2"), ("n2", "r3"), ("n1", "r4")],
            "I1672: every node, at its last row, in that order"
        );
        match &items[0].state {
            AnnouncedOwnerState::Unresolved { reason } => assert!(
                reason.contains("i1672 injected fold failure"),
                "I1672: the reason is the fold's error: {reason}"
            ),
            other => panic!("I1672: the failed node is Unresolved, got {other:?}"),
        }
        assert!(
            items[1..]
                .iter()
                .all(|c| c.state == AnnouncedOwnerState::NotAnnounced),
            "I1672: the other nodes keep their answers"
        );
    }

    /// **I1675** — the one-past cut: more exactly when the executor returned
    /// the row past the page, the page truncated to `limit`, and a refusal
    /// when it returned more (a dropped LIMIT).
    #[test]
    fn i1675_cut_one_past() {
        let mut exact = vec![1, 2, 3];
        assert!(!cut_one_past(&mut exact, 3, "i1675").expect("cut"));
        assert_eq!(exact, vec![1, 2, 3]);
        let mut one_past = vec![1, 2, 3, 4];
        assert!(cut_one_past(&mut one_past, 3, "i1675").expect("cut"));
        assert_eq!(one_past, vec![1, 2, 3]);
        let mut short = vec![1];
        assert!(!cut_one_past(&mut short, 3, "i1675").expect("cut"));
        let mut wide = vec![1, 2, 3, 4, 5];
        let e = cut_one_past(&mut wide, 3, "i1675").expect_err("a dropped LIMIT");
        assert!(
            matches!(&e, Error::Backend(m) if m.starts_with("i1675: 5 rows for a page of 3")),
            "{e:?}"
        );
    }
}
