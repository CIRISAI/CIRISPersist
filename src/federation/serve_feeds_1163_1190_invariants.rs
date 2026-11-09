//! v61.1.0 (CIRISPersist#1190, #1163) — **I1570–I1579: the narrowed serve
//! read and the owner-binding feed**, on sqlite and postgres, through
//! [`FederationDirectory::list_attestations_since_by_prefixes`] and
//! [`FederationDirectory::list_owner_bindings_since`].
//!
//! - **I1570** the prefix read selects the rows whose `dimension` starts
//!   with a dimension prefix OR whose `attestation_type` starts with a type
//!   prefix, oldest serve position first; a prefix is a byte prefix (case
//!   kept), and `%` / `_` are ordinary characters, not `LIKE` wildcards.
//! - **I1571** pages join without a gap or a repeat, `next_cursor` is `Some`
//!   exactly when another row exists (a full last page says so), and a tie on
//!   `admitted_at` is broken by id: a cursor AT the tied instant resumes
//!   inside the tie, after exactly the id it names.
//! - **I1572** it serves what `list_attestations_since` serves: never a
//!   local-tier row, never a tombstoned row unless the tombstone is void for
//!   it (a person-subject row), never a retired carrier, and never an
//!   unregistered type under enforcement (served under report).
//! - **I1573** malformed input is a refusal: a page size outside [1, 10000],
//!   no prefix, an empty prefix, more than 64 prefixes.
//! - **I1574** `high_water`: once nothing remains, it is the stream's head,
//!   past the non-matching rows this read ruled out; a resume from it is
//!   empty, and finds the next matching row.
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
//!   the bound.
//!
//! I1578 is the capsule round trip (`ffi::directory_capsule`); I1579 the
//! sqlite plan (`store::sqlite`).

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::row_type::{with_enforcement, RowTypeEnforcement};
    use crate::federation::steward_purge::{self as sp, PurgePlane};
    use crate::federation::subject_read_1225_invariants::bodies as n;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        attestation_type, cohort_scope, delegation_scope as ds, identity_type as it, owner_binding,
        AnnouncedOwnerState, OwnerBindingChange, ServedAttestationPage,
    };
    use crate::federation::{FederationDirectory, SignedAttestation};
    use chrono::{DateTime, Utc};

    /// A serve position.
    pub(crate) type Pos = (DateTime<Utc>, String);

    /// Raw SQL on the backend under test: the tie and retype plants.
    #[async_trait::async_trait]
    pub(crate) trait RawSql: Sync {
        /// The attestation table, schema-qualified.
        fn attestations_table(&self) -> &'static str;
        /// Run `sql`.
        async fn exec(&self, sql: &str);
    }

    #[cfg(feature = "sqlite")]
    #[async_trait::async_trait]
    impl RawSql for crate::store::sqlite::SqliteBackend {
        fn attestations_table(&self) -> &'static str {
            "federation_attestations"
        }
        async fn exec(&self, sql: &str) {
            self.test_execute(sql).await;
        }
    }

    #[cfg(feature = "postgres")]
    #[async_trait::async_trait]
    impl RawSql for crate::store::postgres::PostgresBackend {
        fn attestations_table(&self) -> &'static str {
            "cirislens.federation_attestations"
        }
        async fn exec(&self, sql: &str) {
            self.test_execute(sql).await;
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

    /// One page of the prefix read.
    pub(crate) async fn page(
        d: &dyn FederationDirectory,
        since: Option<Pos>,
        dims: &[&str],
        types: &[&str],
        limit: i64,
    ) -> ServedAttestationPage {
        d.list_attestations_since_by_prefixes(since, &v(dims), &v(types), limit)
            .await
            .expect("served")
    }

    fn ids(p: &ServedAttestationPage) -> Vec<String> {
        p.items
            .iter()
            .map(|r| r.attestation.attestation_id.clone())
            .collect()
    }

    /// Every page of the prefix read after `since`, `limit` per page: the ids
    /// in order, each page's (row count, next cursor present), and the last
    /// page's `high_water`.
    pub(crate) async fn walk(
        d: &dyn FederationDirectory,
        since: Option<Pos>,
        dims: &[&str],
        types: &[&str],
        limit: i64,
    ) -> (Vec<String>, Vec<(usize, bool)>, Option<Pos>) {
        let mut got = Vec::new();
        let mut shape = Vec::new();
        let mut cursor = since;
        loop {
            let p = page(d, cursor.clone(), dims, types, limit).await;
            shape.push((p.items.len(), p.next_cursor.is_some()));
            got.extend(ids(&p));
            if let Some(next) = &p.next_cursor {
                assert_eq!(
                    p.high_water.as_ref(),
                    Some(next),
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
            .map(|r| (r.attestation.attestation_id.clone(), r.resume_pair()))
            .collect()
    }

    /// **I1570** — the selection, by byte prefix, OR across the two lists.
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

        let all = |p: &ServedAttestationPage| -> Vec<String> { ids(p) };
        assert_eq!(
            all(&page(d, None, &["i1570a:"], &[], 100).await),
            vec![a1.clone(), a2.clone()],
            "I1570 {tag}: one dimension prefix, serve order"
        );
        assert_eq!(
            all(&page(d, None, &["i1570a:", "i1570b:"], &[], 100).await),
            vec![a1.clone(), b1.clone(), a2.clone()],
            "I1570 {tag}: two dimension prefixes are an OR"
        );
        assert_eq!(
            all(&page(d, None, &["i1570A:"], &[], 100).await),
            vec![upper.clone()],
            "I1570 {tag}: a prefix is case-sensitive"
        );
        assert_eq!(
            all(&page(d, None, &[], &["delegates"], 100).await)
                .into_iter()
                .filter(|id| *id == binding)
                .count(),
            1,
            "I1570 {tag}: a type prefix selects the binding"
        );
        assert!(
            !all(&page(d, None, &[], &["delegates"], 100).await)
                .iter()
                .any(|id| [&a1, &b1, &c1, &upper, &a2].contains(&id)),
            "I1570 {tag}: a type prefix selects no `scores` row"
        );
        let both = all(&page(d, None, &["i1570c:"], &["delegates_to"], 100).await);
        assert!(
            both.contains(&c1) && both.contains(&binding) && !both.contains(&a1),
            "I1570 {tag}: a dimension prefix OR a type prefix: {both:?}"
        );
        // `LIKE` wildcards are ordinary bytes: under `LIKE 'i1570_%'` every
        // row above would match, under a byte prefix none does.
        for wild in ["i1570_", "i1570%", "i1570_:", "%"] {
            assert!(
                page(d, None, &[wild], &[wild], 100).await.items.is_empty(),
                "I1570 {tag}: {wild:?} is a literal prefix, not a pattern"
            );
        }
        assert!(
            page(d, None, &["i1570z:"], &[], 100).await.items.is_empty(),
            "I1570 {tag}: a prefix nothing has"
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
        let (all, shape, _) = walk(d, None, &dims, &[], 100).await;
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
            let (got, shape, _) = walk(d, None, &dims, &[], limit).await;
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
        let (got, _, _) = walk(d, None, &dims, &[], 100).await;
        let mut expect = vec![want[0].clone(), want[4].clone()];
        expect.extend(tied.iter().cloned());
        assert_eq!(
            got, expect,
            "I1571 {tag}: the tie sorts after the rest, by id ascending"
        );
        for limit in [1, 2] {
            let (paged, _, _) = walk(d, None, &dims, &[], limit).await;
            assert_eq!(
                paged, expect,
                "I1571 {tag} limit {limit}: a tie larger than the page pages exactly once"
            );
        }
        // A cursor AT the instant: the id decides.
        let at = |id: &str| Some((t, id.to_owned()));
        assert_eq!(
            ids(&page(d, at(""), &dims, &[], 100).await),
            tied,
            "I1571 {tag}: an id below the tie resumes before all of it"
        );
        assert_eq!(
            ids(&page(d, at(&tied[0]), &dims, &[], 100).await),
            tied[1..].to_vec(),
            "I1571 {tag}: the cursor's own id is excluded, the rest of the tie kept"
        );
        assert!(
            page(d, at(&tied[2]), &dims, &[], 100)
                .await
                .items
                .is_empty(),
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
        let dims = ["i1572:"];
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
            "UPDATE {table} SET attestation_type = 'i1572x:unregistered' \
             WHERE attestation_id = '{unregistered}'"
        ))
        .await;
        raw.exec(&format!(
            "UPDATE {table} SET attestation_type = 'holds_bytes:sha256:5a5a5a5a' \
             WHERE attestation_id = '{retired}'"
        ))
        .await;

        let report = with_enforcement(RowTypeEnforcement::Report, async {
            walk(d, None, &dims, &[], 100).await.0
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
            walk(d, None, &dims, &[], 100).await.0
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
            walk(d, None, &dims, &[], 100).await.0
        })
        .await;
        assert_eq!(
            after,
            vec![kept, void, unregistered],
            "I1572 {tag}: a tombstoned row is not served; the person-subject row is"
        );
    }

    /// **I1573** — malformed input is a refusal, never an empty page.
    pub(crate) async fn i1573_malformed_input_is_refused(d: &dyn FederationDirectory, tag: &str) {
        let (a, k) = attester(d, tag).await;
        put_dim(d, &a, &k, "i1573:x:v1").await;
        let one = v(&["i1573:"]);
        for bad in [0, -1, 10_001] {
            d.list_attestations_since_by_prefixes(None, &one, &[], bad)
                .await
                .expect_err("I1573: a page outside [1, 10000] is refused");
        }
        d.list_attestations_since_by_prefixes(None, &[], &[], 10)
            .await
            .expect_err("I1573: no prefix at all is refused");
        d.list_attestations_since_by_prefixes(None, &one, &v(&[""]), 10)
            .await
            .expect_err("I1573: an empty type prefix is refused");
        d.list_attestations_since_by_prefixes(None, &v(&["i1573:", ""]), &[], 10)
            .await
            .expect_err("I1573: an empty dimension prefix is refused");
        let many: Vec<String> = (0..33).map(|i| format!("i1573:{i}:")).collect();
        d.list_attestations_since_by_prefixes(None, &many, &many[..32], 10)
            .await
            .expect_err("I1573: 65 prefixes is refused");
        let page = d
            .list_attestations_since_by_prefixes(None, &many, &many[..31], 10)
            .await
            .expect("I1573: 64 prefixes is served");
        assert!(page.items.is_empty(), "I1573 {tag}");
    }

    /// **I1574** — `high_water` is the head once nothing remains.
    pub(crate) async fn i1574_high_water_passes_ruled_out_rows(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (a, k) = attester(d, tag).await;
        let dims = ["i1574:"];
        let first = put_dim(d, &a, &k, "i1574:a:v1").await;
        let mut others = Vec::new();
        for i in 0..3 {
            others.push(put_dim(d, &a, &k, &format!("i1574x:{i}:v1")).await);
        }
        let pos = positions(d).await;
        let head = pos.values().max().cloned().expect("the stream holds rows");
        assert_eq!(
            Some(&head),
            pos.get(others.last().expect("rows")),
            "I1574 {tag}: the last row put is the head"
        );
        let p = page(d, None, &dims, &[], 100).await;
        assert_eq!(ids(&p), vec![first.clone()], "I1574 {tag}");
        assert!(p.next_cursor.is_none(), "I1574 {tag}: nothing remains");
        assert_eq!(
            p.high_water.as_ref(),
            Some(&head),
            "I1574 {tag}: high_water is the head, past the rows ruled out"
        );
        assert!(
            p.high_water > pos.get(&first).cloned(),
            "I1574 {tag}: high_water is beyond the last match"
        );
        let resumed = page(d, p.high_water.clone(), &dims, &[], 100).await;
        assert!(resumed.items.is_empty(), "I1574 {tag}: nothing new");
        assert_eq!(
            resumed.high_water, p.high_water,
            "I1574 {tag}: an idle resume stays where it was"
        );
        let second = put_dim(d, &a, &k, "i1574:b:v1").await;
        let found = page(d, p.high_water.clone(), &dims, &[], 100).await;
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
    ) -> (Vec<OwnerBindingChange>, Vec<(usize, bool)>, Option<Pos>) {
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
                    assert_eq!(p.high_water.as_ref(), Some(&c));
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
            mine[1].position.1, refresh,
            "I1575 {tag}: the node is reported at its last row"
        );
        assert_ne!(mine[1].position.1, first, "I1575 {tag}");
        assert_eq!(
            mine[0].state,
            AnnouncedOwnerState::NotAnnounced,
            "I1575 {tag}: a binding at self is owned, not announced, and names no owner"
        );
        assert_eq!(mine[0].position.1, private, "I1575 {tag}");
        assert!(
            p.items.iter().all(|c| c.position.1 != unrelated),
            "I1575 {tag}: a scores row is not a candidate"
        );
        assert!(
            p.next_cursor.is_none() && p.high_water.is_some(),
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
        let cursor = cursor.expect("a cursor past the walk");
        let (idle, _, again) = feed(d, Some(cursor.clone()), 2).await;
        assert!(idle.is_empty(), "I1576 {tag}: nothing past the walk");
        assert_eq!(again.as_ref(), Some(&cursor), "I1576 {tag}");

        // The owner withdraws N1's binding; O2 announces N2.
        let w = withdraw(d, &o1, &n1, &live).await;
        let announce = bind(d, &o2, &n2, cohort_scope::FEDERATION).await;
        let (changed, _, _) = feed(d, Some(cursor), 100).await;
        assert_eq!(
            changed
                .iter()
                .map(|c| (c.node_key_id.clone(), c.state.clone(), c.position.1.clone()))
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
        assert!(high.is_some(), "I1577 {tag}: high_water");
        for bad in [0, -1, 10_001] {
            d.list_owner_bindings_since(None, bad)
                .await
                .expect_err("I1577: a page outside [1, 10000] is refused");
        }
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
    on_every_backend!(i1574, bodies::i1574_high_water_passes_ruled_out_rows);
    on_every_backend!(i1575, bodies::i1575_feed_reports_each_node_its_state_now);
    on_every_backend!(i1576, bodies::i1576_removal_arrives_through_the_cursor);
    on_every_backend!(i1577, bodies::i1577_feed_pages_and_refuses);
}
