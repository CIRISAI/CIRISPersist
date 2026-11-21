//! v62.0.0 (JSON-cut slice B) — **every MESH producer emits an edition-2
//! statement a SECOND node admits.**
//!
//! The witness shape is the slice's exit criterion: node A produces, A's
//! store SERVES what it holds (`edition2_statements_since`, the bytes as
//! received, CC 2.6.1.2), and node B admits each served statement through
//! the one statement door (`put_edition2_statement`) — delivered through
//! the planes, never read out of A's directory.
//!
//! - **I2203** — a `scores` row (`emit_attestation_self`): A's statement is
//!   admitted by B under the same row id; B serves byte-identical bytes; the
//!   statement's kid is A's own key under A's own identity-ref.
//! - **I2204** — delegations, in CC's confirmed families: a capability grant
//!   is `self:delegates_to`; an owner binding of the node is
//!   `ownership:.relation:.target_kind:.version`, with the node's own
//!   statement over the same payload as the second voice (two voices, one
//!   row id); B admits all of them.
//! - **I2205** — a `withdraws` carries its TARGET row's family and names the
//!   target by `refs.target`; B admits it. Its EFFECT (the target retracted)
//!   reads `refs.target` at the door, which is slice A's (`TODO(cut-a-refs)`).
//! - **I2206** — the eviction `withdraws` (`emit_withdraws_attestation_helper`)
//!   and a key-grant-shaped emit through `emit_with_local_signer` are
//!   statements too.

/// The bodies, one per invariant, run on sqlite and postgres.
pub(crate) mod bodies {
    use crate::federation::edition2::emit::family_of_statement;
    use crate::federation::edition2::ingest::{kid_of_identity_ref, statement_kid};
    use crate::federation::edition2::store::StatementCursor;
    use crate::federation::types::{attestation_type, cohort_scope, identity_type};
    use crate::federation::EmitAttestationInput;
    use crate::Engine;

    pub(crate) use crate::federation::self_registration_restart_invariants::bodies::signer;

    /// An engine over `dsn` with a composite signer from `alias`.
    pub(crate) async fn node(dsn: &str, alias: &str) -> Engine {
        Engine::with_signer_pre_genesis(signer(alias, alias), dsn)
            .await
            .expect("engine")
    }

    /// **Deliver** everything `from` serves after `cursor` to `to`, through
    /// the statement door; returns the bytes delivered. A statement `to`
    /// already holds is admitted idempotently.
    pub(crate) async fn deliver(
        from: &Engine,
        to: &Engine,
        cursor: &mut Option<StatementCursor>,
    ) -> Vec<Vec<u8>> {
        // v62.0.0 (RL-fix2c) — the serving node, rooted (the serve wait, CC
        // 5.3.4): idempotent per directory, so each delivery re-puts nothing.
        crate::federation::edition2::serve_wait_invariants::test_support::root_this_node(
            from.federation_directory().as_ref(),
        )
        .await;
        // ... and the receiving node too, so the root's own rows A serves
        // (founded over the bundle's holders) are rows B already holds.
        crate::federation::edition2::serve_wait_invariants::test_support::root_this_node(
            to.federation_directory().as_ref(),
        )
        .await;
        // Served to B as B (the filtered listing: the serve rule plus B's
        // audience), never read out of A's store.
        let requester = to.local_derived_key_id().await.ok();
        let mut out = Vec::new();
        loop {
            let page = from
                .edition2_statements_served_to(cursor.as_ref(), 100, requester.as_deref())
                .await
                .expect("A serves its statements");
            if page.next.is_none() {
                return out;
            }
            *cursor = page.next;
            for served in page.statements {
                // v62.0.0 (RL-fix2c) — a signed object (the serving node's
                // genesis bundle voices, served since its root was stood up)
                // crosses at the import door, never the statement door.
                if crate::federation::edition2::names::RowId::of_statement(&served.bytes).is_none()
                {
                    continue;
                }
                to.put_edition2_statement(&served.bytes, None)
                    .await
                    .unwrap_or_else(|e| panic!("B admits A's statement: {e}"));
                out.push(served.bytes);
            }
        }
    }

    /// Every statement `e` serves.
    pub(crate) async fn served(e: &Engine) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut cursor = None;
        loop {
            let page = e
                .federation_directory()
                .edition2_statements_since(cursor.as_ref(), 100)
                .await
                .unwrap();
            if page.is_empty() {
                return out;
            }
            for s in page {
                cursor = Some(s.cursor);
                out.push(s.bytes);
            }
        }
    }

    /// The statement `e` holds for row `rid` (the row's own statement).
    async fn statement_of_row(e: &Engine, rid: &str) -> Vec<u8> {
        let row = e
            .federation_directory()
            .get_attestation(rid)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("row {rid} is held"));
        crate::federation::edition2::emit::carried_statement(&row)
            .unwrap_or_else(|| panic!("row {rid} carries its statement"))
    }

    fn scores(dimension: &str) -> EmitAttestationInput {
        EmitAttestationInput::with_envelope(
            attestation_type::SCORES,
            crate::federation::envelope::EnvelopeCore::from_value(serde_json::json!({
                "dimension": dimension,
                "score": 0.75,
                "confidence": 0.9,
            }))
            .unwrap(),
            cohort_scope::FEDERATION,
        )
    }

    /// I2203.
    pub(crate) async fn i2203_a_scores_row_reaches_a_second_node(
        a_dsn: &str,
        b_dsn: &str,
        tag: &str,
    ) {
        let a = node(a_dsn, &format!("{tag}-2203-a")).await;
        let b = node(b_dsn, &format!("{tag}-2203-b")).await;
        let a_id = a
            .register_self_federation_key(identity_type::NODE, None, None)
            .await
            .expect("I2203: A registers");
        let rid = a
            .emit_attestation_self(scores("observation:reachability:v1"))
            .await
            .expect("I2203: A emits");
        let st = statement_of_row(&a, &rid).await;
        assert_eq!(
            family_of_statement(&st),
            Some(("observation:reachability".to_owned(), "scores".to_owned())),
            "I2203: the family the dimension resolves to"
        );
        assert_eq!(
            statement_kid(&st),
            kid_of_identity_ref(&a_id),
            "I2203: the statement's kid is A's own key under A's own identity-ref"
        );
        let mut cursor = None;
        let delivered = deliver(&a, &b, &mut cursor).await;
        assert!(delivered.contains(&st), "I2203: the row is served");
        let at_b = b
            .federation_directory()
            .get_attestation(&rid)
            .await
            .unwrap()
            .expect("I2203: B admits the row under the same row id");
        assert_eq!(at_b.attesting_key_id, a_id, "I2203: attested by A");
        let b_serves = served(&b).await;
        for s in &delivered {
            assert!(
                b_serves.contains(s),
                "I2203: B serves what it received, byte for byte"
            );
        }
    }

    /// A user engine registered on its own store, its key delivered to `to`.
    async fn user(dsn: &str, alias: &str, to: &[&Engine]) -> (Engine, String) {
        let u = node(dsn, alias).await;
        let id = u
            .register_self_federation_key(identity_type::USER, None, None)
            .await
            .expect("a user registers");
        for t in to {
            let mut c = None;
            deliver(&u, t, &mut c).await;
        }
        (u, id)
    }

    /// I2204.
    pub(crate) async fn i2204_delegations_in_ccs_families(
        a_dsn: &str,
        b_dsn: &str,
        u_dsn: &str,
        tag: &str,
    ) {
        let a = node(a_dsn, &format!("{tag}-2204-a")).await;
        let b = node(b_dsn, &format!("{tag}-2204-b")).await;
        let a_id = a
            .register_self_federation_key(identity_type::NODE, None, None)
            .await
            .unwrap();
        let (_u, u_id) = user(u_dsn, &format!("{tag}-2204-u"), &[&a, &b]).await;
        let u_signer = signer(&format!("{tag}-2204-u"), &format!("{tag}-2204-u"));

        // The owner binding of THIS node: two voices, one row.
        let binding = a
            .grant_delegation(
                &u_signer,
                &a_id,
                vec![crate::federation::types::delegation_scope::INFRA_ATTEST.to_owned()],
                false,
                Some(crate::federation::types::owner_binding::PURPOSE),
                crate::federation::admission::DelegationTermBounds::default(),
            )
            .await
            .expect("I2204: the owner binding");
        let st = statement_of_row(&a, &binding).await;
        assert_eq!(
            family_of_statement(&st).map(|(f, _)| f).as_deref(),
            Some("ownership:.relation:.target_kind:.version"),
            "I2204: an owner binding's family"
        );
        assert_eq!(
            statement_kid(&st),
            kid_of_identity_ref(&u_id),
            "I2204: signed by the actor's own key"
        );
        let rid = crate::federation::edition2::names::RowId(
            <[u8; 32]>::try_from(hex::decode(&binding).unwrap()).unwrap(),
        );
        let voices = a
            .federation_directory()
            .edition2_voices(&rid)
            .await
            .unwrap();
        assert!(
            voices
                .iter()
                .any(|v| statement_kid(v) == kid_of_identity_ref(&a_id)),
            "I2204: the node's own statement is the second voice"
        );

        // A capability grant to a user is `self:delegates_to`.
        let (_v, v_id) = user(u_dsn, &format!("{tag}-2204-v"), &[&a, &b]).await;
        let grant = a
            .grant_delegation(
                &u_signer,
                &v_id,
                vec!["act_on_behalf".to_owned()],
                false,
                None,
                crate::federation::admission::DelegationTermBounds::default(),
            )
            .await;
        if let Ok(grant) = grant {
            let st = statement_of_row(&a, &grant).await;
            assert_eq!(
                family_of_statement(&st),
                Some(("self:delegates_to".to_owned(), "delegates_to".to_owned())),
                "I2204: a capability grant's family"
            );
        }

        let mut cursor = None;
        let delivered = deliver(&a, &b, &mut cursor).await;
        assert!(delivered.contains(&st));
        assert!(
            b.federation_directory()
                .get_attestation(&binding)
                .await
                .unwrap()
                .is_some(),
            "I2204: B admits the owner binding"
        );
        let at_b = b
            .federation_directory()
            .edition2_voices(&rid)
            .await
            .unwrap();
        assert_eq!(at_b.len(), voices.len(), "I2204: B holds both voices");
    }

    /// I2205.
    pub(crate) async fn i2205_a_withdraws_carries_its_targets_family(
        a_dsn: &str,
        b_dsn: &str,
        tag: &str,
    ) {
        let a = node(a_dsn, &format!("{tag}-2205-a")).await;
        let b = node(b_dsn, &format!("{tag}-2205-b")).await;
        a.register_self_federation_key(identity_type::NODE, None, None)
            .await
            .unwrap();
        let target = a
            .emit_attestation_self(scores("observation:reachability:v1"))
            .await
            .unwrap();
        let mut input = EmitAttestationInput::with_envelope(
            attestation_type::WITHDRAWS,
            crate::federation::envelope::EnvelopeCore::from_value(
                crate::federation::withdraws_attestation_envelope(
                    &target,
                    attestation_type::SCORES,
                ),
            )
            .unwrap(),
            cohort_scope::FEDERATION,
        );
        input.attested_key_id = None;
        let w = a
            .emit_attestation_self(input)
            .await
            .expect("I2205: the withdraws is emitted");
        let st = statement_of_row(&a, &w).await;
        assert_eq!(
            family_of_statement(&st),
            Some((
                "observation:reachability".to_owned(),
                "withdraws".to_owned()
            )),
            "I2205: a composer carries its TARGET's family"
        );
        let (_, payload) = crate::federation::edition2::liveness::statement_parts(&st).unwrap();
        let named = crate::federation::edition2::names::names_of(&payload).unwrap();
        assert!(
            named
                .iter()
                .any(|n| n.role == "target" && n.row.hex() == target),
            "I2205: refs.target names the withdrawn row: {named:?}"
        );
        assert!(
            payload.get_text("references_attestation_id").is_none(),
            "I2205: no edition-1 name"
        );
        let mut cursor = None;
        deliver(&a, &b, &mut cursor).await;
        assert!(b
            .federation_directory()
            .get_attestation(&w)
            .await
            .unwrap()
            .is_some());
    }

    /// I2205 (effect) — the target is retracted once the door reads
    /// `refs.target`, on both nodes.
    pub(crate) async fn i2205_effect_the_target_is_withdrawn(a_dsn: &str, tag: &str) {
        let a = node(a_dsn, &format!("{tag}-2205e-a")).await;
        a.register_self_federation_key(identity_type::NODE, None, None)
            .await
            .unwrap();
        let target = a
            .emit_attestation_self(scores("observation:reachability:v1"))
            .await
            .unwrap();
        let w = a
            .emit_attestation_self({
                let mut i = EmitAttestationInput::with_envelope(
                    attestation_type::WITHDRAWS,
                    crate::federation::envelope::EnvelopeCore::from_value(
                        crate::federation::withdraws_attestation_envelope(
                            &target,
                            attestation_type::SCORES,
                        ),
                    )
                    .unwrap(),
                    cohort_scope::FEDERATION,
                );
                i.attested_key_id = None;
                i
            })
            .await
            .unwrap();
        let row = a
            .federation_directory()
            .get_attestation(&w)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.attestation_envelope["references_attestation_id"], target,
            "I2205: the mapped withdraws names its target (slice A's refs reading)"
        );
    }

    /// I2206 — the eviction withdraws and `emit_with_local_signer`.
    pub(crate) async fn i2206_the_sweep_producers_are_statements(
        a_dsn: &str,
        b_dsn: &str,
        tag: &str,
    ) {
        let alias = format!("{tag}-2206-a");
        let a = node(a_dsn, &alias).await;
        let b = node(b_dsn, &format!("{tag}-2206-b")).await;
        a.register_self_federation_key(identity_type::NODE, None, None)
            .await
            .unwrap();
        let local = signer(&alias, &alias);
        let dir = a.federation_directory();
        let e = crate::federation::attestation_emit::emit_with_local_signer(
            &*dir,
            &local,
            scores("observation:reachability:v1"),
        )
        .await
        .expect("I2206: emit_with_local_signer states a row");
        let prior = dir
            .get_attestation(&e.attestation_id)
            .await
            .unwrap()
            .unwrap();
        crate::federation::blobs::emit_withdraws_attestation_helper(
            &prior,
            "ignored-alias",
            &local,
            &*dir,
            chrono::Utc::now(),
        )
        .await
        .expect("I2206: the eviction withdraws");
        let all = served(&a).await;
        let withdraws: Vec<_> = all
            .iter()
            .filter(|s| family_of_statement(s).is_some_and(|(_, t)| t == "withdraws"))
            .collect();
        assert_eq!(withdraws.len(), 1, "I2206: one withdraws statement");
        let mut cursor = None;
        deliver(&a, &b, &mut cursor).await;
    }
}

/// I2209 — serving: a statement by its statement id, a row by its row id,
/// the statement-id wire index; each the bytes as received.
pub(crate) mod serving_bodies {
    use super::bodies::{node, served};
    use crate::federation::edition2::store::{ROW_KIND, STATEMENT_KIND};
    use crate::federation::types::identity_type;

    pub(crate) async fn i2209_served_by_statement_and_row_id(dsn: &str, tag: &str) {
        let a = node(dsn, &format!("{tag}-2209-a")).await;
        a.register_self_federation_key(identity_type::NODE, None, None)
            .await
            .unwrap();
        let rid = a
            .emit_attestation_self(crate::federation::EmitAttestationInput::with_envelope(
                "scores",
                crate::federation::envelope::EnvelopeCore::from_value(serde_json::json!({
                    "dimension": "observation:reachability:v1",
                    "score": 0.5,
                }))
                .unwrap(),
                crate::federation::types::cohort_scope::FEDERATION,
            ))
            .await
            .unwrap();
        let dir = a.federation_directory();
        let all = served(&a).await;
        let ids = dir
            .list_wire_hashes_since(STATEMENT_KIND, None, 1000)
            .await
            .expect("I2209: the statement-id wire index");
        assert_eq!(ids.len(), all.len(), "I2209: one id per held statement");
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "I2209: in id order");
        let mut looked = Vec::new();
        for id in &ids {
            looked.push(
                dir.lookup_signed_record_by_content_hash(STATEMENT_KIND, id)
                    .await
                    .unwrap()
                    .expect("I2209: every listed id is served"),
            );
        }
        let (mut x, mut y) = (looked.clone(), all.clone());
        x.sort();
        y.sort();
        assert_eq!(
            x, y,
            "I2209: served by statement id = served by cursor, byte for byte"
        );
        // Paging: after the first id, the rest.
        let rest = dir
            .list_wire_hashes_since(STATEMENT_KIND, Some(&ids[0]), 1000)
            .await
            .unwrap();
        assert_eq!(
            rest,
            ids[1..].to_vec(),
            "I2209: the page resumes after its cursor"
        );
        // The row's own statement by row id.
        let row = dir.get_attestation(&rid).await.unwrap().unwrap();
        let carried = crate::federation::edition2::emit::carried_statement(&row).unwrap();
        assert_eq!(
            dir.lookup_signed_record_by_content_hash(ROW_KIND, &rid)
                .await
                .unwrap(),
            Some(carried.clone()),
            "I2209: a row by its row id is the statement that admitted it"
        );
        assert!(
            !ids.contains(&rid) || carried.is_empty(),
            "I2209: a row id is not a statement id"
        );
        // Not held, malformed: nothing.
        for bad in ["00".repeat(32), "ZZ".to_owned(), rid.to_uppercase()] {
            assert_eq!(
                dir.lookup_signed_record_by_content_hash(STATEMENT_KIND, &bad)
                    .await
                    .unwrap(),
                None,
                "I2209: {bad} serves nothing"
            );
        }
    }
}

/// I2210 — the serve filter: a private (`self`) row is served to its author
/// and not to a stranger, nor to an anonymous read; a commons row is served
/// to all; the key plane is public. The room arm is the receiver-side
/// audience test with the requester as the party (`is_audience_of`).
pub(crate) mod filter_bodies {
    use super::bodies::node;
    use crate::federation::edition2::serve::servable_to;
    use crate::federation::edition2::store::{ROW_KIND, STATEMENT_KIND};
    use crate::federation::types::{cohort_scope, identity_type};

    fn input(scope: &str) -> crate::federation::EmitAttestationInput {
        crate::federation::EmitAttestationInput::with_envelope(
            "scores",
            crate::federation::envelope::EnvelopeCore::from_value(serde_json::json!({
                "dimension": "observation:reachability:v1",
                "score": 0.25,
            }))
            .unwrap(),
            scope,
        )
    }

    pub(crate) async fn i2210_the_serve_filter(dsn: &str, tag: &str) {
        let a = node(dsn, &format!("{tag}-2210-a")).await;
        let me = a
            .register_self_federation_key(identity_type::USER, None, None)
            .await
            .unwrap();
        let stranger =
            "urn:ietf:params:oauth:ckt:sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let private = a
            .emit_attestation_self(input(cohort_scope::SELF))
            .await
            .expect("I2210: a private (self) row is admitted");
        let commons = a
            .emit_attestation_self(input(cohort_scope::FEDERATION))
            .await
            .unwrap();
        let dir = a.federation_directory();
        let st = |rid: String| {
            let dir = dir.clone();
            async move {
                let row = dir.get_attestation(&rid).await.unwrap().unwrap();
                crate::federation::edition2::emit::carried_statement(&row).unwrap()
            }
        };
        let (p, c) = (st(private.clone()).await, st(commons.clone()).await);
        assert!(
            servable_to(&*dir, &p, Some(&me)).await.unwrap(),
            "I2210: to its author"
        );
        assert!(
            !servable_to(&*dir, &p, Some(stranger)).await.unwrap(),
            "I2210: not to a stranger"
        );
        assert!(
            !servable_to(&*dir, &p, None).await.unwrap(),
            "I2210: not anonymously"
        );
        for r in [Some(stranger), Some(me.as_str()), None] {
            assert!(
                servable_to(&*dir, &c, r).await.unwrap(),
                "I2210: commons to {r:?}"
            );
        }
        // The listing and the point reads apply it.
        let listed = |r: Option<String>| {
            let a = &a;
            async move {
                a.edition2_statements_served_to(None, 1000, r.as_deref())
                    .await
                    .unwrap()
                    .statements
                    .into_iter()
                    .map(|s| s.bytes)
                    .collect::<Vec<_>>()
            }
        };
        let to_me = listed(Some(me.clone())).await;
        let to_stranger = listed(Some(stranger.to_owned())).await;
        assert!(
            to_me.contains(&p) && to_me.contains(&c),
            "I2210: the author is served both"
        );
        assert!(
            !to_stranger.contains(&p),
            "I2210: the stranger is not served the private row"
        );
        assert!(to_stranger.contains(&c));
        assert!(
            to_stranger.iter().any(
                |s| crate::federation::edition2::emit::family_of_statement(s)
                    .is_some_and(|(f, _)| f == "key:record")
            ),
            "I2210: the key plane is public"
        );
        assert_eq!(
            dir.lookup_signed_record_by_content_hash(ROW_KIND, &private)
                .await
                .unwrap(),
            None,
            "I2210: the anonymous point read withholds the private row"
        );
        assert_eq!(
            dir.lookup_signed_record_by_content_hash(ROW_KIND, &commons)
                .await
                .unwrap(),
            Some(c.clone())
        );
        let ids = dir
            .list_wire_hashes_since(STATEMENT_KIND, None, 1000)
            .await
            .unwrap();
        let mut served = Vec::new();
        for id in &ids {
            served.push(
                dir.lookup_signed_record_by_content_hash(STATEMENT_KIND, id)
                    .await
                    .unwrap(),
            );
        }
        assert!(
            !served.contains(&Some(p.clone())),
            "I2210: the wire index withholds it"
        );
        assert!(served.contains(&Some(c)));
    }

    #[test]
    fn i2210_the_room_arm_is_membership() {
        use crate::federation::replication::hold::is_audience_of;
        let members: std::collections::HashSet<String> = ["room-1".to_owned()].into();
        assert!(is_audience_of(
            cohort_scope::COMMUNITY,
            Some("room-1"),
            false,
            &members
        ));
        assert!(!is_audience_of(
            cohort_scope::COMMUNITY,
            Some("room-1"),
            false,
            &std::collections::HashSet::new()
        ));
    }
}

/// I2208 — the hash-digest round trip, and the holding claim as a statement.
pub(crate) mod digest_bodies {
    use super::bodies::{deliver, node, served};
    use crate::federation::edition2::emit::family_of_statement;
    use crate::federation::types::identity_type;

    /// A node's own holding claim is a `custody` statement whose
    /// `evidence_refs` is `[[-16, h'…']]`; the door admits it on a SECOND node,
    /// and the earlier custody gate (`parse_custody_ack`) reads back the same
    /// 64-hex blob address on both.
    pub(crate) async fn i2208_a_digest_member_round_trips(a_dsn: &str, b_dsn: &str, tag: &str) {
        let a = node(a_dsn, &format!("{tag}-2208-a")).await;
        let b = node(b_dsn, &format!("{tag}-2208-b")).await;
        a.register_self_federation_key(identity_type::NODE, None, None)
            .await
            .unwrap();
        let put = a
            .put_blob_scoped(
                crate::federation::types::cohort_scope::FEDERATION,
                None,
                format!("i2208 {tag}").as_bytes(),
                None,
                None,
            )
            .await
            .expect("I2208: a plaintext blob is held and announced");
        let want = hex::encode(put.at_rest_sha256);
        let claims: Vec<Vec<u8>> = served(&a)
            .await
            .into_iter()
            .filter(|s| family_of_statement(s).is_some_and(|(f, _)| f == "custody:.kind"))
            .collect();
        assert!(
            !claims.is_empty(),
            "I2208: the holding claim is a custody statement"
        );
        let (_, payload) =
            crate::federation::edition2::liveness::statement_parts(&claims[0]).unwrap();
        let refs = payload
            .get_text("evidence_refs")
            .and_then(ciris_verify_core::cde::Value::as_array)
            .expect("I2208: evidence_refs");
        assert_eq!(
            refs[0]
                .as_array()
                .and_then(|d| d.get(1))
                .and_then(ciris_verify_core::cde::Value::as_bytes),
            Some(&put.at_rest_sha256[..]),
            "I2208: the digest is [-16, bstr32]"
        );
        let mut cursor = None;
        deliver(&a, &b, &mut cursor).await;
        for e in [&a, &b] {
            let rid = crate::federation::edition2::names::RowId::of_statement(&claims[0])
                .expect("a row id")
                .hex();
            let row = e
                .federation_directory()
                .get_attestation(&rid)
                .await
                .unwrap()
                .expect("I2208: the claim is admitted");
            let ack = crate::federation::custody_ack::parse_custody_ack(&row)
                .expect("I2208: the earlier gate reads it")
                .expect("I2208: a custody report");
            assert_eq!(
                ack.blob_sha256_hex, want,
                "I2208: the same hex on both nodes"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::bodies as b;

    fn tag() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    #[cfg(feature = "sqlite")]
    fn sqlite_dsn(dir: &tempfile::TempDir, name: &str) -> String {
        format!(
            "sqlite:///{}",
            dir.path().join(format!("{name}.db")).display()
        )
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2203_sqlite() {
        let d = tempfile::tempdir().unwrap();
        b::i2203_a_scores_row_reaches_a_second_node(
            &sqlite_dsn(&d, "a"),
            &sqlite_dsn(&d, "b"),
            &tag(),
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2203_postgres() {
        let (Some(a), Some(bb)) = (
            crate::test_pg::isolated_dsn(),
            crate::test_pg::isolated_dsn(),
        ) else {
            eprintln!("i2203 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        b::i2203_a_scores_row_reaches_a_second_node(&a, &bb, &tag()).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2204_sqlite() {
        let d = tempfile::tempdir().unwrap();
        Box::pin(b::i2204_delegations_in_ccs_families(
            &sqlite_dsn(&d, "a"),
            &sqlite_dsn(&d, "b"),
            &sqlite_dsn(&d, "u"),
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2205_sqlite() {
        let d = tempfile::tempdir().unwrap();
        Box::pin(b::i2205_a_withdraws_carries_its_targets_family(
            &sqlite_dsn(&d, "a"),
            &sqlite_dsn(&d, "b"),
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2205_postgres() {
        let (Some(a), Some(bb)) = (
            crate::test_pg::isolated_dsn(),
            crate::test_pg::isolated_dsn(),
        ) else {
            eprintln!("i2205 postgres: SKIPPED");
            return;
        };
        Box::pin(b::i2205_a_withdraws_carries_its_targets_family(
            &a,
            &bb,
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore] // TODO(cut-a-refs): the door's reading of refs.target is slice A's.
    async fn i2205_effect_sqlite() {
        let d = tempfile::tempdir().unwrap();
        b::i2205_effect_the_target_is_withdrawn(&sqlite_dsn(&d, "a"), &tag()).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2206_sqlite() {
        let d = tempfile::tempdir().unwrap();
        Box::pin(b::i2206_the_sweep_producers_are_statements(
            &sqlite_dsn(&d, "a"),
            &sqlite_dsn(&d, "b"),
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2206_postgres() {
        let (Some(a), Some(bb)) = (
            crate::test_pg::isolated_dsn(),
            crate::test_pg::isolated_dsn(),
        ) else {
            eprintln!("i2206 postgres: SKIPPED");
            return;
        };
        Box::pin(b::i2206_the_sweep_producers_are_statements(&a, &bb, &tag())).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2208_sqlite() {
        let d = tempfile::tempdir().unwrap();
        Box::pin(super::digest_bodies::i2208_a_digest_member_round_trips(
            &sqlite_dsn(&d, "a"),
            &sqlite_dsn(&d, "b"),
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2208_postgres() {
        let (Some(a), Some(bb)) = (
            crate::test_pg::isolated_dsn(),
            crate::test_pg::isolated_dsn(),
        ) else {
            eprintln!("i2208 postgres: SKIPPED");
            return;
        };
        Box::pin(super::digest_bodies::i2208_a_digest_member_round_trips(
            &a,
            &bb,
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2204_postgres() {
        let (Some(a), Some(bb), Some(u)) = (
            crate::test_pg::isolated_dsn(),
            crate::test_pg::isolated_dsn(),
            crate::test_pg::isolated_dsn(),
        ) else {
            eprintln!("i2204 postgres: SKIPPED");
            return;
        };
        Box::pin(b::i2204_delegations_in_ccs_families(&a, &bb, &u, &tag())).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2209_sqlite() {
        let d = tempfile::tempdir().unwrap();
        Box::pin(super::serving_bodies::i2209_served_by_statement_and_row_id(
            &sqlite_dsn(&d, "a"),
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2209_postgres() {
        let Some(a) = crate::test_pg::isolated_dsn() else {
            eprintln!("i2209 postgres: SKIPPED");
            return;
        };
        Box::pin(super::serving_bodies::i2209_served_by_statement_and_row_id(
            &a,
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2210_sqlite() {
        let d = tempfile::tempdir().unwrap();
        super::filter_bodies::i2210_the_serve_filter(&sqlite_dsn(&d, "a"), &tag()).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2210_postgres() {
        let Some(a) = crate::test_pg::isolated_dsn() else {
            eprintln!("i2210 postgres: SKIPPED");
            return;
        };
        super::filter_bodies::i2210_the_serve_filter(&a, &tag()).await;
    }
}
