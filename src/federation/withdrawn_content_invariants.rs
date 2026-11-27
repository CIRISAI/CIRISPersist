//! v62.0.0 (WD-fix1; CC 2.4.1.1, CC 6.1.5 N5) — **I4400–I4411: an admitted
//! author / subject withdrawal makes the target's content descend.**
//! sqlite and postgres; the peer legs deliver through the real serve feed
//! (`edition2::serve::statements_served_to` → the statement door).
//!
//! - **I4400** the author withdraws (rule 1, `Engine::withdraw_statement`):
//!   on the author's node the row, its statements and the bytes only it bound
//!   are gone; its id reads `Withdrawn` naming the withdrawal; the withdrawal
//!   is held, stamped rule 1. A late copy of the row and of the bytes is
//!   refused by the tombstone.
//! - **I4401** a PERSON subject withdraws (rule 2) a row about them: the
//!   interim person-subject void is lifted for this basis only, re-derived;
//!   node B (holding the row and its own copy of the bytes) receives the
//!   withdrawal through the feed and its sweep descends the same content; a
//!   re-offer to B is refused; the two nodes converge.
//! - **I4402** a tombstone that only CLAIMS the descent basis (no stored
//!   admitted withdrawal names the row) is void for a person-subject row as
//!   before, at every site: `purge_finalize`, the backend delete door, the
//!   serve read.
//! - **I4403** a row an admitted `moderation:*` act names is withdrawn by its
//!   author: readers hide it (the bytes fold reads it withdrawn), and nothing
//!   descends, on the author's node AND on a peer that received the room, the
//!   row, the act and the withdrawal through the feed: the row and the bytes
//!   stay on both.
//! - **I4404** the sweep: not yet run → caught up; a restart (a fresh
//!   Engine on the same store, with no LocalSigner) rescans without deleting
//!   twice or erroring, and each tick says whether it read to the end.
//! - **I4405** the shape decides: a withdrawn CLAIM leaves this holder; a
//!   withdrawn STRUCTURAL row (a membership acceptance) is kept, read
//!   retracted.
//! - **I4407** (in `steward_purge_invariants`' I655) a finalized purge, any
//!   basis, deletes the purged row's statement bytes.
//! - **I4408** the keep asks about the node's OWNER (its cosigned owner
//!   binding), never an identity the node hosts: a node hosting many people
//!   keeps none of their withdrawn rows by the operator's switch.
//! - **I4409** (WD-fix3 rev 2) two nodes through the serve feed into EACH
//!   door (the Engine's, the directory's, the capsule op, the JSON
//!   `put_attestation` door direct and through the capsule (WD-fix4); the PyO3
//!   feed methods in `ffi::pyo3`'s tests), both arrival orders: B descends in the
//!   door's own admission, no sweep; a later copy is refused; both read
//!   `Withdrawn`.
//! - **I4410** (WD-fix3) the withdrawal row purged after the descent: a later
//!   copy of the person-subject row is still refused by the descent's own
//!   finalized tombstone.
//! - **I4411** (WD-fix3 rev 2) a descent the door could not finish (a
//!   directory with no bytes plane; what a crash leaves) finishes at the next
//!   open.
//! - **I4416** (WD-fix9b; CC 3.3.6) the occurrence producer by kind: a
//!   person's first device (its genesis key) concludes on one pen; an
//!   unowned agent states nothing; the next call with the owner's pen
//!   states the owner binding and then the bind; a later device waits for
//!   its own statement, then concludes.
//! - **I4406** (unit) the one rule table, the shape table (its counts, as
//!   Constitution's file states them), the one keep switch.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::at_rest_cascade::blob_invariants::node_signer;
    use crate::federation::at_rest_cascade::orchestrate::put_blob_scoped;
    use crate::federation::blob_tombstone::{binding_state, BindingState};
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::steward_purge as sp;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, cohort_scope};
    use crate::federation::withdrawn_content::{HeldRowState, SweepState};
    use crate::federation::{Attestation, BlobStorage, FederationDirectory};

    pub(crate) fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..10].to_owned()
    }

    /// `body` sealed at the commons by `signer`; its at-rest sha.
    async fn seal<B>(b: &B, signer: &crate::signing::LocalSigner, body: &[u8]) -> [u8; 32]
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        put_blob_scoped(b, signer, cohort_scope::FEDERATION, None, body, None, None)
            .await
            .unwrap_or_else(|e| panic!("seal: {e}"))
            .at_rest_sha256
    }

    /// A federation-tier `scores` row by `author` binding `sha` by
    /// `evidence_refs`, about `subjects`, through the statement door.
    /// Returns the stored row (its id is the node-computed row id).
    async fn content_row<B>(
        b: &B,
        author: &str,
        subjects: &[&str],
        sha: &[u8; 32],
        extra: serde_json::Value,
    ) -> Attestation
    where
        B: FederationDirectory + Sync,
    {
        let mut env = serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "dimension": "file:v1",
            "cohort_scope": "federation",
            "evidence_refs": [hex::encode(sha)],
        });
        if let (Some(o), Some(x)) = (env.as_object_mut(), extra.as_object()) {
            for (k, v) in x {
                o.insert(k.clone(), v.clone());
            }
        }
        let id = env["id"].as_str().unwrap_or_default().to_owned();
        let mut row = ts::bare_attestation(&id, author, author, &env);
        row.attestation_type = attestation_type::SCORES.into();
        row.cohort_scope = env["cohort_scope"]
            .as_str()
            .unwrap_or(cohort_scope::FEDERATION)
            .to_owned();
        row.subject_key_ids = subjects.iter().map(|s| (*s).to_owned()).collect();
        let stored = e2::try_put_row(b, &row, author)
            .await
            .unwrap_or_else(|e| panic!("content_row: {e}"));
        b.get_attestation(&e2::rid(&stored))
            .await
            .expect("content_row: reads")
            .expect("content_row: landed")
    }

    /// How many held statements carry row `id` (row statement and voices).
    async fn statements_of(d: &dyn FederationDirectory, id: &str) -> usize {
        use crate::federation::edition2::names::RowId;
        let (mut n, mut cursor) = (0, None);
        loop {
            let page = d
                .edition2_statements_since(cursor.as_ref(), 500)
                .await
                .expect("the statement listing");
            if page.is_empty() {
                break;
            }
            cursor = page.last().map(|st| st.cursor);
            n += page
                .iter()
                .filter(|st| RowId::of_statement(&st.bytes).map(|r| r.hex()).as_deref() == Some(id))
                .count();
        }
        n
    }

    /// [`deliver_to`] the commons.
    async fn deliver(from: &dyn FederationDirectory, to: &dyn FederationDirectory) {
        deliver_to(from, to, None).await;
    }

    /// Deliver `from`'s feed as served to `requester` (`None`: the commons)
    /// to `to` through the statement door.
    async fn deliver_to(
        from: &dyn FederationDirectory,
        to: &dyn FederationDirectory,
        requester: Option<&str>,
    ) {
        use crate::federation::edition2::ingest::{put_statement, INGEST_TIER};
        let mut cursor = None;
        loop {
            let page = crate::federation::edition2::serve::statements_served_to(
                from,
                cursor.as_ref(),
                256,
                requester,
            )
            .await
            .expect("the serve listing");
            for st in &page.statements {
                let _ = put_statement(to, &st.bytes, None, INGEST_TIER).await;
            }
            let Some(next) = page.next else { break };
            cursor = Some(next);
        }
    }

    async fn sweep_to_end(e: &crate::Engine) -> u32 {
        let mut descended = 0;
        loop {
            let t = e
                .sweep_withdrawn_content_once(64)
                .await
                .expect("the sweep runs");
            descended += t.descended;
            if t.exhausted {
                return descended;
            }
        }
    }

    /// The row's original statement (a late copy of it).
    fn statement_of(row: &Attestation) -> Vec<u8> {
        e2::carried_statement(row).expect("an edition-2 row carries its statement")
    }

    /// **I4400.**
    pub(super) async fn i4400_the_author_withdraws<B>(b: &B, e: &crate::Engine, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let d: &dyn FederationDirectory = b.as_dyn_directory();
        let signer = node_signer(b, &format!("i4400-author-{s}")).await;
        let author = signer.derived_key_id();
        let body = format!("i4400 the author's file {s}");
        let sha = seal(b, &signer, body.as_bytes()).await;
        let row = content_row(b, &author, &[], &sha, serde_json::json!({})).await;
        let id = row.attestation_id.clone();
        let late = statement_of(&row);
        assert!(
            statements_of(d, &id).await > 0,
            "I4400 premise: its statement is held"
        );

        // WD-fix3 — the verb answers LANDED or HELD (KR-fix21): the row id of
        // a landed one.
        let wid = crate::federation::withdraw_statement_invariants::landed_id(
            e.withdraw_statement(&signer, &id)
                .await
                .expect("I4400: the author withdraws their own row"),
            "I4400",
        );
        let w = d
            .get_attestation(&wid)
            .await
            .expect("I4400: reads")
            .expect("I4400: the withdrawal is held: it verifies alone");
        assert_eq!(w.withdraws_admission_rule, Some(1), "I4400: stamped rule 1");
        assert!(
            d.get_attestation(&id)
                .await
                .expect("I4400: reads")
                .is_none(),
            "I4400: the row descended"
        );
        assert_eq!(
            statements_of(d, &id).await,
            0,
            "I4400: its statements descended"
        );
        assert!(
            !b.has_blob(&sha).await.expect("I4400: reads"),
            "I4400: its bytes descended"
        );
        match e.held_row_state(&id).await.expect("I4400: reads") {
            HeldRowState::Withdrawn {
                withdraws_attestation_id,
                ..
            } => assert_eq!(
                withdraws_attestation_id, wid,
                "I4400: named by its withdrawal"
            ),
            other => panic!("I4400: a descended id is a NAMED state, not {other:?}"),
        }
        // A late copy of the row, and of the bytes, is refused by the tombstone.
        let err = e2::put_statement(d, &late)
            .await
            .expect_err("I4400: a late copy of the row is refused");
        assert_eq!(
            err.kind(),
            sp::token::TOMBSTONED,
            "I4400: by the tombstone: {err}"
        );
        let err = put_blob_scoped(
            b,
            &signer,
            cohort_scope::FEDERATION,
            None,
            body.as_bytes(),
            None,
            None,
        )
        .await
        .expect_err("I4400: the bytes fetched later are refused");
        assert_eq!(
            err.kind(),
            sp::token::BLOB_PURGED,
            "I4400: by the tombstone: {err}"
        );
    }

    /// **I4401.**
    pub(super) async fn i4401_a_person_subject_withdraws_and_a_peer_converges<B>(
        a: (&B, &crate::Engine),
        bnode: (&B, &crate::Engine),
        s: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let (ba, ea) = a;
        let (bb, eb) = bnode;
        let (da, db): (&dyn FederationDirectory, &dyn FederationDirectory) =
            (ba.as_dyn_directory(), bb.as_dyn_directory());
        let (author_l, subject_l) = (format!("i4401-author-{s}"), format!("i4401-subject-{s}"));
        let author_s = node_signer(ba, &author_l).await;
        let subject_s = node_signer(ba, &subject_l).await;
        let _ = node_signer(bb, &author_l).await;
        let _ = node_signer(bb, &subject_l).await;
        let (author, subject) = (author_s.derived_key_id(), subject_s.derived_key_id());
        let body = format!("i4401 a file about the subject {s}");
        let sha = seal(ba, &author_s, body.as_bytes()).await;
        let row = content_row(ba, &author, &[&subject], &sha, serde_json::json!({})).await;
        let id = row.attestation_id.clone();
        assert!(
            sp::person_subject_of(da, &row)
                .await
                .expect("I4401: reads")
                .is_some(),
            "I4401 premise: a person is the row's subject (the interim void applies)"
        );
        // B holds the row and its own copy of the bytes BEFORE the withdrawal.
        deliver(da, db).await;
        let sha_b = seal(bb, &author_s, body.as_bytes()).await;
        assert_eq!(sha_b, sha, "I4401 premise: the same bytes");
        assert!(
            db.get_attestation(&id).await.expect("reads").is_some(),
            "I4401: B holds it"
        );

        let wid = crate::federation::withdraw_statement_invariants::landed_id(
            ea.withdraw_statement(&subject_s, &id)
                .await
                .expect("I4401: the subject withdraws a row about them"),
            "I4401",
        );
        let w = da
            .get_attestation(&wid)
            .await
            .expect("reads")
            .expect("held");
        assert_eq!(w.withdraws_admission_rule, Some(2), "I4401: stamped rule 2");
        assert!(
            da.get_attestation(&id).await.expect("reads").is_none(),
            "I4401: A: the person-subject row descended (the void is lifted for this basis)"
        );
        assert!(
            !ba.has_blob(&sha).await.expect("reads"),
            "I4401: A: the bytes descended"
        );

        // B: before the withdrawal arrives, B still holds both.
        assert!(
            bb.has_blob(&sha).await.expect("reads"),
            "I4401: B holds until it learns"
        );
        deliver(da, db).await;
        assert!(
            db.get_attestation(&wid).await.expect("reads").is_some(),
            "I4401: B received the withdrawal through the feed"
        );
        // WD-fix3 rev 2 — the statement door descends in its own admission:
        // B's row is gone before any sweep, and a sweep has nothing left.
        assert!(
            db.get_attestation(&id).await.expect("reads").is_none(),
            "I4401: B: gone at the door"
        );
        let descended = sweep_to_end(eb).await;
        assert_eq!(descended, 0, "I4401: the door already descended it");
        assert!(
            !bb.has_blob(&sha).await.expect("reads"),
            "I4401: B: the bytes are gone"
        );
        assert_eq!(
            statements_of(db, &id).await,
            0,
            "I4401: B: its statements are gone"
        );
        let err = e2::put_statement(db, &statement_of(&row))
            .await
            .expect_err("I4401: a re-offer to B is refused");
        assert_eq!(err.kind(), sp::token::TOMBSTONED, "I4401: {err}");
        for (n, e) in [("A", ea), ("B", eb)] {
            assert!(
                matches!(
                    e.held_row_state(&id).await.expect("reads"),
                    HeldRowState::Withdrawn { .. }
                ),
                "I4401: {n} converges on Withdrawn"
            );
        }
    }

    /// **I4402.**
    pub(super) async fn i4402_a_claimed_basis_lifts_nothing<B>(b: &B, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let d: &dyn FederationDirectory = b.as_dyn_directory();
        let author_s = node_signer(b, &format!("i4402-author-{s}")).await;
        let subject_s = node_signer(b, &format!("i4402-subject-{s}")).await;
        let (author, subject) = (author_s.derived_key_id(), subject_s.derived_key_id());
        let sha = seal(b, &author_s, format!("i4402 {s}").as_bytes()).await;
        let row = content_row(b, &author, &[&subject], &sha, serde_json::json!({})).await;
        let id = row.attestation_id.clone();
        // A tombstone CLAIMING the descent basis, derived from a row that is
        // no admitted withdrawal of it.
        let notice = crate::federation::subject_erasure::ErasureNotice::descent(
            &format!("not-a-withdrawal-{s}"),
            &id,
        );
        let (execution, tombstones) = crate::federation::subject_erasure::withdrawal_execution(
            &notice,
            &author,
            sp::WITHDRAWAL_DESCENT_BASIS,
            vec![(
                sp::PurgePlane::Attestation,
                id.clone(),
                Some(format!("not-a-withdrawal-{s}")),
            )],
            &author,
            sp::origin::LOCAL,
            chrono::Utc::now(),
            None,
        )
        .expect("I4402: the execution");
        d.purge_put_execution(&execution, &tombstones)
            .await
            .expect("I4402: the claimed tombstone is written");
        // The Rust site.
        assert!(
            sp::tombstone_void_reason(d, &row)
                .await
                .expect("reads")
                .is_some(),
            "I4402: tombstone_void_reason: still void"
        );
        assert!(
            !sp::withdrawal_descent_lifts(d, &row).await.expect("reads"),
            "I4402: no stored admitted withdrawal names it"
        );
        // The delete door's own SQL.
        assert!(
            !d.purge_delete_tombstoned_attestation(&id)
                .await
                .expect("the door"),
            "I4402: the backend delete door deletes nothing"
        );
        // purge_finalize.
        let report = sp::purge_finalize(d, &execution.notice_id, None)
            .await
            .expect("I4402: finalize");
        assert!(
            report.voided.contains(&format!("attestation:{id}")),
            "I4402: finalize reports it void: {report:?}"
        );
        assert!(
            d.get_attestation(&id).await.expect("reads").is_some(),
            "I4402: kept"
        );
        // The serve read's SQL.
        let mut served = false;
        let mut since = None;
        loop {
            let page = d
                .list_attestations_since(since.clone(), 500)
                .await
                .expect("serve");
            if page.is_empty() {
                break;
            }
            served |= page.iter().any(|r| r.attestation.attestation_id == id);
            let last = page.last().expect("non-empty");
            since = Some((last.admitted_at, last.attestation.attestation_id.clone()));
        }
        assert!(
            served,
            "I4402: the serve read still serves the person-subject row"
        );
    }

    /// **I4403.**
    pub(super) async fn i4403_a_cited_row_does_not_descend<B>(
        a: (&B, &crate::Engine),
        peer: (&B, &crate::Engine),
        s: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::membership_acceptance_invariants::bodies::{found_community, reg};
        let (b, e) = a;
        let (bb, eb) = peer;
        let d: &dyn FederationDirectory = b.as_dyn_directory();
        let db: &dyn FederationDirectory = bb.as_dyn_directory();
        let author_l = format!("i4403-author-{s}");
        let author_s = node_signer(b, &author_l).await;
        let _ = node_signer(bb, &author_l).await;
        let author = author_s.derived_key_id();
        let moderator = format!("i4403-mod-{s}");
        let room = format!("i4403-room-{s}");
        for dir in [d, db] {
            e2::put_key(
                dir,
                &moderator,
                &[crate::federation::types::identity_type::USER],
            )
            .await;
            reg(dir, &[&room]).await;
        }
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let room = found_community(d, &room, "quorum:1/1", &[&moderator, &author], &[])
            .await
            .expect("I4403: the room");
        let room_k = e2::kid_or_keep(&room);
        let body = format!("i4403 {s}");
        let sha = seal(b, &author_s, body.as_bytes()).await;
        let row = content_row(
            b,
            &author,
            &[],
            &sha,
            serde_json::json!({
                "community_id": room_k,
                "community_key_id": room_k,
                "cohort_scope": cohort_scope::COMMUNITY,
            }),
        )
        .await;
        // The moderator's act names the row (CC 4.5.5's shape, I1512's).
        let env = serde_json::json!({
            "dimension": "moderation:rogue_vote:v1",
            "score": crate::federation::namespace::registry::in_class_score(
                "moderation:rogue_vote:v1"
            ),
            "confidence": 0.9,
            "community_id": room_k,
            "community_key_id": room_k,
            "references_attestation_id": row.attestation_id,
        });
        let mut act = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            &moderator,
            &moderator,
            &env,
        );
        act.attestation_type = attestation_type::SCORES.into();
        act.weight = None;
        act.cohort_scope = cohort_scope::COMMUNITY.into();
        let act = e2::row_of(&act, &moderator);
        d.put_attestation(crate::federation::SignedAttestation { attestation: act })
            .await
            .expect("I4403: the moderator's act is admitted");
        let id = row.attestation_id.clone();
        // The peer holds the room, the row, the act and its own copy of the
        // bytes, through the feed, BEFORE the withdrawal.
        let mod_k = e2::kid(&moderator);
        deliver_to(d, db, Some(&mod_k)).await;
        assert_eq!(
            seal(bb, &author_s, body.as_bytes()).await,
            sha,
            "I4403 premise"
        );
        assert!(
            db.get_attestation(&id).await.expect("reads").is_some(),
            "I4403 premise: the peer holds the row"
        );
        e.withdraw_statement(&author_s, &id)
            .await
            .expect("I4403: the author withdraws");
        let held = d
            .get_attestation(&id)
            .await
            .expect("reads")
            .expect("I4403: the cited row is NOT destroyed");
        assert!(
            b.has_blob(&sha).await.expect("reads"),
            "I4403: the bytes do not descend"
        );
        assert!(
            matches!(
                binding_state(d, &sha).await.expect("reads"),
                BindingState::Withdrawn { .. }
            ),
            "I4403: readers hide it: the bytes read withdrawn"
        );
        assert!(
            crate::federation::withdrawn_content::accountability_citation(d, &held)
                .await
                .expect("reads")
                .is_some(),
            "I4403: cited by the act"
        );
        assert_eq!(
            sweep_to_end(e).await,
            0,
            "I4403: the sweep descends nothing"
        );
        assert!(
            d.get_attestation(&id).await.expect("reads").is_some(),
            "I4403: still kept"
        );
        // The PEER: the withdrawal arrives through the feed; the peer holds
        // the act too, so its own sweep keeps the row and the bytes.
        deliver_to(d, db, Some(&mod_k)).await;
        assert!(
            db.list_withdrawals_since(None, 100)
                .await
                .expect("reads")
                .iter()
                .any(|w| w.attestation.attesting_key_id == author),
            "I4403: the peer received the withdrawal"
        );
        assert_eq!(
            sweep_to_end(eb).await,
            0,
            "I4403: the peer descends nothing"
        );
        assert!(
            db.get_attestation(&id).await.expect("reads").is_some(),
            "I4403: the peer keeps the cited row"
        );
        assert!(
            bb.has_blob(&sha).await.expect("reads"),
            "I4403: and the bytes"
        );
    }

    /// **I4404.**
    pub(super) async fn i4404_the_sweep_is_resumable<B>(
        b: &B,
        e: &crate::Engine,
        b_arc: std::sync::Arc<dyn FederationDirectory>,
        s: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let d: &dyn FederationDirectory = b.as_dyn_directory();
        assert_eq!(
            e.withdrawn_content_sweep_state().await,
            SweepState::NotYetRun,
            "I4404: not yet run"
        );
        let signer = node_signer(b, &format!("i4404-author-{s}")).await;
        let author = signer.derived_key_id();
        let double = crate::federation::directory_double::FaultInjectingDirectory::new(b_arc);
        let mut ids = Vec::new();
        let mut wids: Vec<String> = Vec::new();
        // WD-fix19 — the pass-17 red: the sweep's reader listed ONE of three
        // withdrawals (only the last). Asked after EVERY step of every
        // iteration, so the red names the step after which an earlier
        // withdrawal stops being listed, and whether its row is gone
        // (`get_attestation`) or merely unlisted.
        async fn still_listed(d: &dyn FederationDirectory, wids: &[String], step: &str) {
            let listed: Vec<(String, String, String)> = d
                .list_withdrawals_since(None, 16)
                .await
                .expect("I4404: list the withdrawals")
                .into_iter()
                .map(|w| {
                    (
                        w.admitted_at.to_rfc3339(),
                        w.attestation.attestation_id,
                        w.attestation.attestation_type,
                    )
                })
                .collect();
            for wid in wids {
                if listed.iter().any(|(_, id, _)| id == wid) {
                    continue;
                }
                let row = d.get_attestation(wid).await.expect("reads");
                panic!(
                    "I4404 premise: after {step}, withdrawal {wid} is no longer listed; its row \
                     is {}: listed {listed:?}",
                    match row {
                        Some(r) => format!(
                            "HELD (type {}, admitted rule {:?})",
                            r.attestation_type, r.withdraws_admission_rule
                        ),
                        None => "GONE".to_owned(),
                    }
                );
            }
        }
        for i in 0..3 {
            let sha = seal(b, &signer, format!("i4404 {i} {s}").as_bytes()).await;
            still_listed(d, &wids, &format!("iteration {i}'s seal")).await;
            let row = content_row(b, &author, &[], &sha, serde_json::json!({})).await;
            still_listed(d, &wids, &format!("iteration {i}'s content row")).await;
            // WD-fix3 rev 2 — withdrawn through a directory that carries no
            // bytes plane: the door's own descent deletes the row and stops
            // at the bytes (unfinalized), and only a later pass finishes it.
            let target = row.clone();
            let mut w = ts::bare_attestation(
                &uuid::Uuid::new_v4().to_string(),
                &author,
                &author,
                &serde_json::json!({"references_attestation_id": target.attestation_id}),
            );
            w.attestation_type = attestation_type::WITHDRAWS.into();
            w.cohort_scope = cohort_scope::FEDERATION.into();
            let st = e2::statement_of_family(&w, &author, &e2::family_of(&target));
            // WD-fix10 — the premise each tick needs, asserted where it is
            // made: the withdrawal LANDS (a `Row`, stored, stamped rule 1).
            // Pass 5's red (one withdrawal examined of three) is then named
            // at the put that did not land.
            let out = e2::put_statement(&double, &st)
                .await
                .expect("I4404: the withdrawal");
            assert!(
                matches!(
                    out,
                    crate::federation::edition2::ingest::StatementOutcome::Row { .. }
                ),
                "I4404 premise: withdrawal {i} lands: {out:?}"
            );
            let wid = crate::federation::edition2::names::RowId::of_statement(&st)
                .expect("I4404: the withdrawal names its row")
                .hex();
            assert_eq!(
                d.get_attestation(&wid)
                    .await
                    .expect("reads")
                    .and_then(|w| w.withdraws_admission_rule),
                Some(1),
                "I4404 premise: withdrawal {i} is stored, stamped rule 1"
            );
            assert!(
                b.has_blob(&sha).await.expect("reads"),
                "I4404 premise: the bytes wait for a pass"
            );
            ids.push((row.attestation_id.clone(), sha));
            wids.push(wid);
            still_listed(d, &wids, &format!("iteration {i}'s withdrawal")).await;
        }
        // WD-fix13 — the premise of a cut-short tick, from the reader the
        // sweep itself uses (`list_withdrawals_since`, admission order), on
        // the store the test wrote AND on the Engine's own directory: all
        // three withdrawals are listed (with their admission instants, so a
        // red names which went missing, or which store the Engine reads).
        let engine_dir = e.federation_directory();
        for (what, dir) in [
            ("the store", d),
            ("the Engine's directory", engine_dir.as_ref()),
        ] {
            let listed: Vec<(String, String, String)> = dir
                .list_withdrawals_since(None, 16)
                .await
                .expect("I4404: list the withdrawals")
                .into_iter()
                .map(|w| {
                    (
                        w.admitted_at.to_rfc3339(),
                        w.attestation.attestation_id,
                        w.attestation.attestation_type,
                    )
                })
                .collect();
            assert!(
                wids.iter()
                    .all(|wid| listed.iter().any(|(_, id, _)| id == wid)),
                "I4404 premise: {what} lists all three withdrawals {wids:?}: {listed:?}"
            );
        }
        let t = e
            .sweep_withdrawn_content_once(2)
            .await
            .expect("I4404: tick 1");
        assert!(!t.exhausted, "I4404: a tick cut short says so: {t:?}");
        assert_eq!(e.withdrawn_content_sweep_state().await, SweepState::Behind);
        let rest = sweep_to_end(e).await;
        assert_eq!(t.descended + rest, 3, "I4404: three descend, once each");
        assert_eq!(
            e.withdrawn_content_sweep_state().await,
            SweepState::CaughtUp
        );
        // The restart: a fresh Engine on the same store, no LocalSigner.
        let restarted = crate::Engine::from_shared(e.backend().clone(), e.signer().clone());
        assert_eq!(
            restarted.withdrawn_content_sweep_state().await,
            SweepState::NotYetRun,
            "I4404: a restart has not run"
        );
        assert_eq!(
            sweep_to_end(&restarted).await,
            0,
            "I4404: the rescan deletes nothing twice"
        );
        assert_eq!(
            restarted.withdrawn_content_sweep_state().await,
            SweepState::CaughtUp
        );
        for (id, sha) in ids {
            assert!(
                d.get_attestation(&id).await.expect("reads").is_none(),
                "I4404: {id}"
            );
            assert!(
                !b.has_blob(&sha).await.expect("reads"),
                "I4404: bytes of {id}"
            );
        }
    }

    /// **I4405.**
    pub(super) async fn i4405_structure_is_kept_a_claim_descends<B>(
        b: &B,
        e: &crate::Engine,
        s: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::membership_acceptance_invariants::bodies::{
            found_community, id_of, proposal, put_e2, reg, reply,
        };
        use crate::federation::withdrawn_content::{shape_of, FamilyShape};
        let d: &dyn FederationDirectory = b.as_dyn_directory();
        // A CLAIM (a score about something, no bytes): the row goes.
        let signer = node_signer(b, &format!("i4405-author-{s}")).await;
        let author = signer.derived_key_id();
        let env = serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "dimension": "expertise:cardiology:en:v1",
            "score": crate::federation::namespace::registry::in_class_score(
                "expertise:cardiology:en:v1"
            ),
            "confidence": 0.9,
        });
        let mut r = ts::bare_attestation(
            env["id"].as_str().unwrap_or_default(),
            &author,
            &author,
            &env,
        );
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = cohort_scope::FEDERATION.into();
        let stored = e2::try_put_row(b, &r, &author)
            .await
            .expect("I4405: the claim");
        let claim = e2::rid(&stored);
        let held = d
            .get_attestation(&claim)
            .await
            .expect("reads")
            .expect("held");
        assert_eq!(
            shape_of(&held),
            Some(FamilyShape::Claim),
            "I4405 premise: a claim"
        );
        e.withdraw_statement(&signer, &claim)
            .await
            .expect("I4405: withdrawn");
        assert!(
            d.get_attestation(&claim).await.expect("reads").is_none(),
            "I4405: a withdrawn claim leaves this holder (the claim arm)"
        );
        // STRUCTURE (a membership acceptance): kept, read retracted, so acts
        // under it are still judged as of their own instant.
        let (cid, founder, k_seed) = (
            format!("i4405-c-{s}"),
            format!("i4405-f-{s}"),
            format!("i4405-k-{s}"),
        );
        reg(d, &[&cid, &founder, &k_seed]).await;
        let (cid, founder, k) = (id_of(&cid), id_of(&founder), id_of(&k_seed));
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let cid = found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .expect("I4405: the room");
        let now = chrono::Utc::now();
        let p = proposal(
            &founder,
            cohort_scope::COMMUNITY,
            &cid,
            &k,
            None,
            now,
            Some(chrono::Duration::days(7)),
        );
        put_e2(d, &p).await.expect("I4405: the invitation");
        let acceptance = reply(&k, &k, &p, true, now);
        put_e2(d, &acceptance).await.expect("I4405: K accepts");
        let aid = e2::rid(&acceptance);
        let held = d.get_attestation(&aid).await.expect("reads").expect("held");
        assert!(
            matches!(
                shape_of(&held),
                Some(FamilyShape::ConsentDoor | FamilyShape::Consent | FamilyShape::Door)
            ),
            "I4405 premise: a structural row: {:?}",
            shape_of(&held)
        );
        e.withdraw_statement(&ts::local_signer(&k_seed), &aid)
            .await
            .expect("I4405: K withdraws the acceptance");
        assert!(
            d.get_attestation(&aid).await.expect("reads").is_some(),
            "I4405: a withdrawn structural row is kept, read retracted"
        );
    }

    /// **I4408.**
    pub(super) async fn i4408_the_keep_asks_the_nodes_owner(d: &dyn FederationDirectory, s: &str) {
        use crate::federation::types::identity_type::{NODE, USER};
        use crate::federation::withdrawn_content::{
            disposition, node_relation, Disposition, KeepPolicy, NodeRelation,
        };
        let (owner_s, node_s, hosted_s, lone_s) = (
            format!("i4408-owner-{s}"),
            format!("i4408-node-{s}"),
            format!("i4408-hosted-{s}"),
            format!("i4408-lone-node-{s}"),
        );
        for k in [&owner_s, &hosted_s] {
            ts::register_identity_key(d, k, USER).await;
        }
        for k in [&node_s, &lone_s] {
            ts::register_identity_key(d, k, NODE).await;
        }
        ts::put_owner_binding(d, &owner_s, &node_s).await;
        let (owner, node, hosted, lone) = (
            e2::kid(&owner_s),
            e2::kid(&node_s),
            e2::kid(&hosted_s),
            e2::kid(&lone_s),
        );
        let row = |by: &str, subjects: &[&str]| {
            let mut r = ts::bare_attestation(
                &uuid::Uuid::new_v4().to_string(),
                by,
                by,
                &serde_json::json!({"dimension": "file:v1"}),
            );
            r.subject_key_ids = subjects.iter().map(|x| (*x).to_owned()).collect();
            r
        };
        let on = KeepPolicy {
            signer_keeps: true,
            named_party_keeps: true,
        };
        // A hosted identity that is not the node's owner: the operator's
        // switch does not keep its rows.
        let (w, t) = (row(&hosted, &[]), row(&hosted, &[]));
        let rel = node_relation(d, &node, &w, &t).await.expect("I4408: reads");
        assert_eq!(
            rel,
            NodeRelation::OtherHolder,
            "I4408: a hosted identity is not the owner"
        );
        assert_eq!(
            disposition(rel, 1, on),
            Disposition::Descend,
            "I4408: it descends"
        );
        // The owner's own withdrawal: the signer's own node.
        let (w, t) = (row(&owner, &[]), row(&owner, &[]));
        let rel = node_relation(d, &node, &w, &t).await.expect("I4408: reads");
        assert_eq!(rel, NodeRelation::SignersOwnNode, "I4408: the owner's node");
        assert_eq!(disposition(rel, 1, on), Disposition::KeepAtSelf);
        // A row ABOUT the owner that its signer (hosted) withdrew: a named
        // party's own node, which keeps only what the signer withdrew.
        let (w, t) = (row(&hosted, &[]), row(&hosted, &[&owner]));
        let rel = node_relation(d, &node, &w, &t).await.expect("I4408: reads");
        assert_eq!(
            rel,
            NodeRelation::NamedPartysOwnNode,
            "I4408: the named party's node"
        );
        assert_eq!(disposition(rel, 1, on), Disposition::KeepAtSelf);
        assert_eq!(
            disposition(rel, 2, on),
            Disposition::Descend,
            "I4408: rule 2 is not the signer's"
        );
        // A node with no owner binding keeps nobody's rows.
        let (w, t) = (row(&owner, &[]), row(&owner, &[]));
        let rel = node_relation(d, &lone, &w, &t).await.expect("I4408: reads");
        assert_eq!(rel, NodeRelation::OtherHolder, "I4408: no owner, no keep");
    }

    // ── WD-fix3: whichever arrived first, through every door ───────────────

    /// v62.0.0 (WD-fix3 rev 2) — the door a witness feeds node B through.
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Door {
        /// The Engine's replicated door (`Engine::apply_replicated_statement_at_feed`).
        Engine,
        /// The directory's replicated door (`ingest::apply_replicated_statement`
        /// over the backend: the server's ingest, a host with no Engine).
        Directory,
        /// The capsule proxy's `ApplyReplicatedStatement` op (the door runs on
        /// the host's store).
        Capsule,
        /// v62.0.0 (WD-fix4) — the JSON attestation door
        /// (`put_attestation`, the PyO3 `put_attestation` method's and the
        /// capsule `PutAttestation` op's door) given the row A holds, which
        /// carries its statement: routed into the statement funnel.
        Json,
        /// The same JSON door through the capsule proxy (`PutAttestation`).
        JsonCapsule,
    }

    /// Offer `bytes` to node B through `door`. A statement that names no row
    /// (none here) goes through the directory's plain statement door.
    async fn offer_through(
        door: Door,
        eb: &crate::Engine,
        db: &dyn FederationDirectory,
        proxy: &dyn FederationDirectory,
        bytes: &[u8],
        json_row: Option<&Attestation>,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::edition2::ingest::{apply_replicated_statement, INGEST_TIER};
        use crate::federation::edition2::names::RowId;
        // WD-fix4 — the JSON door takes the row (carrying this statement);
        // what is not a row (a key record, a further voice) goes through the
        // statement door, as a JSON host's feed would carry it.
        if let (Door::Json | Door::JsonCapsule, Some(row)) = (door, json_row) {
            let to = if matches!(door, Door::Json) {
                db
            } else {
                proxy
            };
            return to
                .put_attestation(crate::federation::SignedAttestation {
                    attestation: row.clone(),
                })
                .await
                .map(|_| ());
        }
        let Some(id) = RowId::of_statement(bytes) else {
            return crate::federation::edition2::ingest::put_statement(
                db,
                bytes,
                None,
                INGEST_TIER,
            )
            .await
            .map(|_| ());
        };
        match door {
            Door::Engine => {
                let feed = crate::federation::edition2::accord_rescan::FeedPosition {
                    plane: "statements".to_owned(),
                    peer: "wd-fix3-peer".to_owned(),
                    position: id.hex(),
                };
                eb.apply_replicated_statement_at_feed(bytes, &id.0, &feed)
                    .await
                    .map(|_| ())
            }
            Door::Directory | Door::Json => apply_replicated_statement(db, bytes, &id.0)
                .await
                .map(|_| ()),
            Door::Capsule | Door::JsonCapsule => apply_replicated_statement(proxy, bytes, &id.0)
                .await
                .map(|_| ()),
        }
    }

    /// `from`'s feed as served to the commons, in serve order.
    pub(crate) async fn served_feed(from: &dyn FederationDirectory) -> Vec<Vec<u8>> {
        let mut cursor = None;
        let mut out = Vec::new();
        loop {
            let page = crate::federation::edition2::serve::statements_served_to(
                from,
                cursor.as_ref(),
                256,
                None,
            )
            .await
            .expect("the serve listing");
            out.extend(page.statements.into_iter().map(|st| st.bytes));
            let Some(next) = page.next else { break };
            cursor = Some(next);
        }
        out
    }

    /// Deliver `from`'s feed to node B through `door`. A statement the door
    /// refuses or keeps waiting is skipped, as a feed puller moves on.
    async fn deliver_through(
        door: Door,
        from: &dyn FederationDirectory,
        eb: &crate::Engine,
        db: &dyn FederationDirectory,
        proxy: &dyn FederationDirectory,
    ) {
        for st in served_feed(from).await {
            // The row A holds for this statement, when it IS that row's
            // carried statement (the JSON doors' form).
            let row = match crate::federation::edition2::names::RowId::of_statement(&st) {
                Some(id) => from
                    .get_attestation(&id.hex())
                    .await
                    .expect("reads")
                    .filter(|r| statement_of(r) == st),
                None => None,
            };
            let _ = offer_through(door, eb, db, proxy, &st, row.as_ref()).await;
        }
    }

    /// v62.0.0 (WD-fix3 rev 2) — one I4409 case: the author on node A, a
    /// content row binding bytes, and node B's own copy of the bytes.
    pub(crate) struct WdCase {
        /// The author's signer (A).
        pub(crate) author: std::sync::Arc<crate::signing::LocalSigner>,
        /// The row's id.
        pub(crate) id: String,
        /// The row's statement, as a third party that held it would offer it.
        pub(crate) late_copy: Vec<u8>,
        /// The bytes it binds.
        pub(crate) sha: [u8; 32],
        /// The row as A held it (carrying its statement): the JSON doors'
        /// late copy.
        pub(crate) row: Attestation,
    }

    /// Set up a [`WdCase`] on A, with the author's key and its own copy of
    /// the bytes on B.
    pub(crate) async fn wd_case<A, B>(ba: &A, bb: &B, s: &str) -> WdCase
    where
        A: BlobStorage + FederationDirectory + Sync,
        B: BlobStorage + FederationDirectory + Sync,
    {
        let author_l = format!("i4409-author-{s}");
        let author = node_signer(ba, &author_l).await;
        let _ = node_signer(bb, &author_l).await;
        let body = format!("i4409 a file {s}");
        let sha = seal(ba, &author, body.as_bytes()).await;
        let row = content_row(
            ba,
            &author.derived_key_id(),
            &[],
            &sha,
            serde_json::json!({}),
        )
        .await;
        let sha_b = seal(bb, &author, body.as_bytes()).await;
        assert_eq!(sha_b, sha, "I4409 premise: the same bytes");
        WdCase {
            author,
            id: row.attestation_id.clone(),
            late_copy: statement_of(&row),
            sha,
            row,
        }
    }

    /// The author withdraws on A (A descends); the withdrawal's id.
    pub(crate) async fn wd_withdraw<A>(
        ba: &A,
        ea: &crate::Engine,
        case: &WdCase,
        what: &str,
    ) -> String
    where
        A: BlobStorage + FederationDirectory + Sync,
    {
        let wid = crate::federation::withdraw_statement_invariants::landed_id(
            ea.withdraw_statement(&case.author, &case.id)
                .await
                .expect("the author withdraws"),
            what,
        );
        assert!(
            ba.get_attestation(&case.id).await.expect("reads").is_none(),
            "{what}: A descended"
        );
        wid
    }

    /// The withdrawal-first premise on B: the row was never held, the
    /// withdrawal waits unstamped (no attestation row).
    pub(crate) async fn wd_assert_waiting(
        db: &dyn FederationDirectory,
        case: &WdCase,
        wid: &str,
        what: &str,
    ) {
        assert!(
            db.get_attestation(&case.id).await.expect("reads").is_none(),
            "{what} premise: B never held the row (A no longer serves it)"
        );
        assert!(
            db.get_attestation(wid).await.expect("reads").is_none(),
            "{what} premise: B keeps the withdrawal waiting (link_unheld), unstamped"
        );
    }

    /// B descended in the door's own admission: the withdrawal stamped rule
    /// 1, the row, its statements and B's bytes gone, a later copy refused,
    /// and both nodes read `Withdrawn` naming the withdrawal.
    pub(crate) async fn wd_assert_descended<B>(
        ea: &crate::Engine,
        bb: &B,
        case: &WdCase,
        wid: &str,
        what: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let db = bb.as_dyn_directory();
        let w = db
            .get_attestation(wid)
            .await
            .expect("reads")
            .unwrap_or_else(|| panic!("{what}: B holds the withdrawal"));
        assert_eq!(
            w.withdraws_admission_rule,
            Some(1),
            "{what}: B stamped rule 1"
        );
        assert!(
            db.get_attestation(&case.id).await.expect("reads").is_none(),
            "{what}: B descended the row at the door (no sweep ran)"
        );
        assert_eq!(
            statements_of(db, &case.id).await,
            0,
            "{what}: B holds none of its statements"
        );
        assert!(
            !bb.has_blob(&case.sha).await.expect("reads"),
            "{what}: B's copy of the bytes descended"
        );
        let err = e2::put_statement(db, &case.late_copy)
            .await
            .expect_err("a later copy to B is refused");
        assert_eq!(err.kind(), sp::token::TOMBSTONED, "{what}: {err}");
        let states = [
            ("A", ea.held_row_state(&case.id).await.expect("reads")),
            (
                "B",
                crate::federation::withdrawn_content::held_row_state(db, &case.id)
                    .await
                    .expect("reads"),
            ),
        ];
        for (n, st) in states {
            match st {
                HeldRowState::Withdrawn {
                    withdraws_attestation_id,
                    ..
                } => assert_eq!(withdraws_attestation_id, wid, "{what}: {n}"),
                other => panic!("{what}: {n} converges on Withdrawn, not {other:?}"),
            }
        }
    }

    /// **I4409** — two nodes, the serve feed delivered to node B through
    /// `door` (the Engine's, the directory's, the capsule's), in BOTH
    /// arrival orders: B descends the row in the door's own admission, with
    /// no sweep. `withdrawal_first`: B receives the withdrawal before it
    /// holds the row (it waits `link_unheld`), then a third party's copy of
    /// the row; the row's arrival re-folds and stamps the withdrawal, and the
    /// re-conclusion descends the row before the door returns. Otherwise B
    /// holds the row first and the withdrawal's admission descends it.
    pub(super) async fn i4409_descent_at_every_door<B>(
        a: (&B, &crate::Engine),
        bnode: (&B, &crate::Engine, std::sync::Arc<dyn FederationDirectory>),
        door: Door,
        withdrawal_first: bool,
        s: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let (ba, ea) = a;
        let (bb, eb, b_arc) = bnode;
        let proxy = crate::ffi::directory_capsule::test_proxy(b_arc);
        let (da, db): (&dyn FederationDirectory, &dyn FederationDirectory) =
            (ba.as_dyn_directory(), bb.as_dyn_directory());
        let what = format!(
            "I4409 ({door:?} door, {})",
            if withdrawal_first {
                "withdrawal first"
            } else {
                "row first"
            }
        );
        let case = wd_case(ba, bb, s).await;
        if !withdrawal_first {
            deliver_through(door, da, eb, db, proxy.as_ref()).await;
            assert!(
                db.get_attestation(&case.id).await.expect("reads").is_some(),
                "{what} premise: B holds the row before the withdrawal"
            );
        }
        let wid = wd_withdraw(ba, ea, &case, &what).await;
        deliver_through(door, da, eb, db, proxy.as_ref()).await;
        if withdrawal_first {
            wd_assert_waiting(db, &case, &wid, &what).await;
            // WD-fix4 rev 2 — the JSON door answers a held row as it did
            // before the routing (the gate's error), while the statement is
            // now kept and folded (held `link_unheld`), so the target's
            // arrival concludes it.
            if matches!(door, Door::Json | Door::JsonCapsule) {
                let w_row = da
                    .get_attestation(&wid)
                    .await
                    .expect("reads")
                    .expect("A holds the withdrawal");
                let to = if matches!(door, Door::Json) {
                    db
                } else {
                    proxy.as_ref()
                };
                let err = to
                    .put_attestation(crate::federation::SignedAttestation {
                        attestation: w_row.clone(),
                    })
                    .await
                    .expect_err("a held row answers the error it answered before");
                // WD-fix6 — the structural test tells this HOLD from a refusal.
                assert!(
                    crate::federation::attestation_admit::kept_waiting(db, &w_row)
                        .await
                        .expect("reads"),
                    "{what}: kept_waiting: the held withdrawal is a hold"
                );
                assert!(
                    err.to_string().contains("target")
                        || err.kind() == "federation_withdraws_target_unheld",
                    "{what}: the held answer names the wait: {err}"
                );
                let id = crate::federation::edition2::store::id_of_hex(&wid)
                    .map(crate::federation::edition2::names::RowId)
                    .expect("a row id");
                let state = db
                    .fold_state(&id)
                    .await
                    .expect("reads")
                    .unwrap_or_else(|| panic!("{what}: the statement is kept"));
                assert_eq!(
                    state.held.map(|h| h.reason).as_deref(),
                    Some(crate::federation::edition2::fold::reason::LINK_UNHELD),
                    "{what}: kept, held link_unheld"
                );
            }
            offer_through(
                door,
                eb,
                db,
                proxy.as_ref(),
                &case.late_copy,
                Some(&case.row),
            )
            .await
            .unwrap_or_else(|e| panic!("{what}: the row's copy is admitted at B: {e}"));
        }
        wd_assert_descended(ea, bb, &case, &wid, &what).await;
        // WD-fix4 — the JSON door refuses the late copy by the tombstone too.
        if matches!(door, Door::Json | Door::JsonCapsule) {
            let to = if matches!(door, Door::Json) {
                db
            } else {
                proxy.as_ref()
            };
            let err = to
                .put_attestation(crate::federation::SignedAttestation {
                    attestation: case.row.clone(),
                })
                .await
                .expect_err("a later JSON copy to B is refused");
            assert!(
                err.to_string().contains(sp::token::TOMBSTONED),
                "{what}: by the tombstone: {err}"
            );
            // WD-fix6 — a REFUSAL keeps nothing: the structural test says so.
            assert!(
                !crate::federation::attestation_admit::kept_waiting(db, &case.row)
                    .await
                    .expect("reads"),
                "{what}: kept_waiting: a refused copy is not a hold"
            );
        }
    }

    /// **I4410** — the withdrawal row is purged after the descent: a later
    /// copy of the descended row is STILL refused by the descent's own
    /// finalized tombstone, though no stored withdrawal names the row any
    /// more. The row's subject is a person (the interim void applies to it);
    /// its author is an agent key, so the withdrawal (which names the row's
    /// `attested_key_id`, the author) has no person subject and a purge can
    /// delete it. Before WD-fix3 the person void let the copy back in.
    pub(super) async fn i4410_a_purged_withdrawal_leaves_the_descent_standing<B>(
        b: &B,
        e: &crate::Engine,
        s: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::types::identity_type::AGENT;
        let d: &dyn FederationDirectory = b.as_dyn_directory();
        let author_l = format!("i4410-author-{s}");
        ts::register_hybrid_key_as(b, &author_l, &author_l, AGENT).await;
        let author_s = ts::local_signer(&author_l);
        ts::register_hybrid_key_as(b, &author_s.derived_key_id(), &author_l, AGENT).await;
        let _ = author_s.federation_id().await;
        let subject_s = node_signer(b, &format!("i4410-subject-{s}")).await;
        let (author, subject) = (author_s.derived_key_id(), subject_s.derived_key_id());
        let sha = seal(
            b,
            &author_s,
            format!("i4410 about the subject {s}").as_bytes(),
        )
        .await;
        let row = content_row(b, &author, &[&subject], &sha, serde_json::json!({})).await;
        let id = row.attestation_id.clone();
        let late_copy = statement_of(&row);
        assert!(
            sp::person_subject_of(d, &row)
                .await
                .expect("reads")
                .is_some(),
            "I4410 premise: a person is the row's subject"
        );

        let wid = crate::federation::withdraw_statement_invariants::landed_id(
            e.withdraw_statement(&subject_s, &id)
                .await
                .expect("I4410: the subject withdraws"),
            "I4410",
        );
        let w = d
            .get_attestation(&wid)
            .await
            .expect("reads")
            .expect("I4410: the withdrawal is held");
        assert_eq!(w.withdraws_admission_rule, Some(2), "I4410: rule 2");
        assert!(
            d.get_attestation(&id).await.expect("reads").is_none(),
            "I4410: descended"
        );
        assert!(
            sp::person_subject_of(d, &w).await.expect("reads").is_none(),
            "I4410 premise: the withdrawal has no person subject (it can be purged)"
        );

        // A purge removes the withdrawal row: a finalized steward-basis
        // header and tombstone on it (the header the steward door writes;
        // written here directly, as I4402 writes its claimed one), settled.
        let at = sp::purge_clock() - chrono::Duration::seconds(sp::PURGE_SETTLE_DWELL_SECS + 60);
        let notice = crate::federation::subject_erasure::ErasureNotice::descent(
            &format!("i4410-purge-{s}"),
            &wid,
        );
        let (execution, tombstones) = crate::federation::subject_erasure::withdrawal_execution(
            &notice,
            &subject,
            sp::STEWARD_PURGE_BASIS,
            vec![(sp::PurgePlane::Attestation, wid.clone(), None)],
            &subject,
            sp::origin::LOCAL,
            at,
            None,
        )
        .expect("I4410: the purge header");
        d.purge_put_execution(&execution, &tombstones)
            .await
            .expect("I4410: the purge is recorded");
        sp::purge_finalize(d, &execution.notice_id, None)
            .await
            .expect("I4410: the purge finalizes");
        assert!(
            d.get_attestation(&wid).await.expect("reads").is_none(),
            "I4410 premise: the withdrawal row is gone"
        );
        assert!(
            !sp::withdrawal_descent_lifts(d, &row).await.expect("reads"),
            "I4410 premise: no stored withdrawal names the row now"
        );
        assert!(
            sp::descent_outlived_its_withdrawal(d, &row)
                .await
                .expect("reads"),
            "I4410: the descent's finalized tombstone stands by itself"
        );

        let err = e2::put_statement(d, &late_copy)
            .await
            .expect_err("I4410: a later copy is refused");
        assert_eq!(err.kind(), sp::token::TOMBSTONED, "I4410: {err}");
        assert!(
            d.get_attestation(&id).await.expect("reads").is_none(),
            "I4410: the person-subject row did not come back"
        );
        assert!(
            matches!(
                e.held_row_state(&id).await.expect("reads"),
                HeldRowState::Withdrawn { .. }
            ),
            "I4410: still Withdrawn"
        );
    }

    /// **I4414** (WD-fix9; the lead's ruling) — **a first login writes no
    /// unsigned occurrence.** `self_at_login` without the identity's signer
    /// (the identity's pen is elsewhere), with each device's own pen in hand:
    ///
    /// - WD-fix9b (the Constitution's ruling of 2026-11-22, CC 3.3.6: "an
    ///   UNOWNED agent has no occurrence") — the unowned agent states
    ///   NOTHING: it is pending, with no draft and no row, signed or not;
    ///   (a NODE is not this case: its self pair, owned or not, concludes
    ///   on its one statement, one pen: I3532 — the Constitution retracted
    ///   the node wait, P/FREEZE.md);
    /// - the app's bind under the login identity keeps the app's own voice
    ///   and returns the identity's part as a DRAFT; it is pending;
    /// - no occurrence row exists under the identity, and the app is no
    ///   device of it: no self-DEK audience, no roster seat, it does not act
    ///   for the identity;
    /// - the identity's holder signs the draft and the node submits it
    ///   (`Engine::submit_voice`): the bind concludes, and the app is then a
    ///   device, a roster key, and acts for the identity.
    pub(super) async fn i4414_a_first_login_writes_no_unsigned_occurrence<B>(
        b: &B,
        e: &crate::Engine,
        s: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
        use crate::federation::types::device_class;
        use crate::federation::types::identity_type::{AGENT, USER};
        let d = b.as_dyn_directory();
        let identity_label = format!("i4414-id-{s}");
        let identity_signer = ts::local_signer(&identity_label);
        let identity = identity_signer.federation_id().await;
        ts::register_hybrid_key_as(b, &identity, &identity_label, USER).await;
        let (app, agent) = (
            e2::kid(&format!("i4414-app-{s}")),
            e2::kid(&format!("i4414-agent-{s}")),
        );
        ts::register_hybrid_key_as(b, &app, &app, USER).await;
        ts::register_hybrid_key_as(b, &agent, &agent, AGENT).await;
        let occ = |key: &str, class: &str| SelfAtLoginOccurrence {
            occurrence_key_id: key.to_owned(),
            device_class: class.to_owned(),
            hardware_attestation: None,
            encryption_pubkeys: None,
            transport_destinations: vec![],
            identity_key_id: None,
            occurrence_signer: Some(ts::local_signer(&e2::seed_of(key))),
            transport: None,
        };
        let out = e
            .self_at_login(SelfAtLoginInput {
                identity_key_id: identity.clone(),
                identity_signer: None,
                app: occ(&app, device_class::PHONE),
                agent: occ(&agent, device_class::AGENT),
                bilateral_pair_id: uuid::Uuid::new_v4().to_string(),
                delegation_scope: None,
            })
            .await
            .expect("I4414: the first login completes without the identity's pen");
        assert!(
            out.occurrences_published.is_empty(),
            "I4414: nothing concludes without the identity's pen: {out:?}"
        );
        assert_eq!(
            out.occurrences_pending,
            vec![app.clone(), agent.clone()],
            "I4414: the app waits for the identity's voice, the unowned agent for an owner: \
             {out:?}"
        );
        assert!(
            !out.bind_drafts.iter().any(|(k, _)| k == &agent),
            "I4414: nothing is drafted for the unowned agent: {out:?}"
        );
        // NO unsigned occurrence row: nothing under the identity yet, and
        // nothing at all for the unowned agent.
        assert!(
            d.list_identity_occurrences_for(&identity)
                .await
                .unwrap()
                .is_empty(),
            "I4414: no occurrence row under the identity before its voice"
        );
        assert!(
            d.list_signed_identity_occurrences_for(&agent)
                .await
                .unwrap()
                .is_empty()
                && d.list_identity_occurrences_for(&agent)
                    .await
                    .unwrap()
                    .is_empty(),
            "I4414: an unowned agent has no occurrence"
        );
        // The app's own voice is KEPT; the identity's part is a draft.
        let draft = out
            .bind_drafts
            .iter()
            .find(|(k, _)| k == &app)
            .map(|(_, dr)| dr.clone())
            .expect("I4414: the identity's part is returned as a draft");
        let row_id =
            crate::federation::edition2::names::RowId::of_statement(&draft.assemble(Vec::new()))
                .expect("I4414: the draft names the bind's row");
        assert!(
            !d.edition2_voices(&row_id).await.unwrap().is_empty(),
            "I4414: the app's own voice is kept"
        );
        // Until the identity's voice: no device, no seat, no acting for it.
        let now = chrono::Utc::now();
        let is_device = |list: Vec<crate::federation::types::IdentityOccurrence>| {
            list.iter().any(|o| o.occurrence_key_id == app)
        };
        assert!(
            !is_device(
                crate::federation::replication_audience::devices_of(d, &identity)
                    .await
                    .unwrap()
            ),
            "I4414: not yet a device of the identity (no self-DEK audience)"
        );
        assert!(
            !crate::federation::self_roster::roster_now(d, &identity)
                .await
                .unwrap()
                .contains(&app),
            "I4414: no roster seat before the identity's voice"
        );
        assert!(
            !crate::federation::self_roster::acts_as_steward_at(d, &identity, &app, now)
                .await
                .unwrap(),
            "I4414: does not act for the identity before its voice"
        );
        // The identity's holder signs the draft; the node submits it.
        let statement = draft.assemble(
            identity_signer
                .sign_composite(&draft.sig_structure)
                .await
                .expect("I4414: the identity signs"),
        );
        let seated = e
            .submit_voice(&statement)
            .await
            .expect("I4414: the identity's voice is admitted");
        assert!(seated.is_seated(), "I4414: the bind concludes: {seated:?}");
        assert!(
            is_device(d.list_identity_occurrences_for(&identity).await.unwrap()),
            "I4414: the app's occurrence now exists under the identity"
        );
        assert!(
            is_device(
                crate::federation::replication_audience::devices_of(d, &identity)
                    .await
                    .unwrap()
            ),
            "I4414: a device of the identity"
        );
        assert!(
            crate::federation::self_roster::roster_now(d, &identity)
                .await
                .unwrap()
                .contains(&app),
            "I4414: a roster seat"
        );
        assert!(
            crate::federation::self_roster::acts_as_steward_at(
                d,
                &identity,
                &app,
                chrono::Utc::now()
            )
            .await
            .unwrap(),
            "I4414: it acts for the identity"
        );
        // The node itself is unaffected: its own key record is held.
        let node = e.local_derived_key_id().await.expect("the node's id");
        assert!(
            d.lookup_public_key(&node).await.unwrap().is_some(),
            "I4414: the node's own key stands"
        );
    }

    /// **I4415** (WD-fix9 rev 2; the common case: the node holds the
    /// identity's pen in-process) — `self_at_login` WITH the identity's
    /// signer and each device's own pen: both voices of the app's bind are
    /// signed in the one call and it concludes at once; nothing is pending,
    /// no draft is returned, and the app is at once a device of the identity,
    /// a roster key, and acts for it. No unsigned row is written on this
    /// path either (every occurrence row is a signed bind).
    pub(super) async fn i4415_a_login_with_the_identity_pen_concludes_at_once<B>(
        b: &B,
        e: &crate::Engine,
        s: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
        use crate::federation::types::device_class;
        use crate::federation::types::identity_type::{AGENT, USER};
        let d = b.as_dyn_directory();
        let identity_label = format!("i4415-id-{s}");
        let identity_signer = ts::local_signer(&identity_label);
        let identity = identity_signer.federation_id().await;
        ts::register_hybrid_key_as(b, &identity, &identity_label, USER).await;
        let (app, agent) = (
            e2::kid(&format!("i4415-app-{s}")),
            e2::kid(&format!("i4415-agent-{s}")),
        );
        ts::register_hybrid_key_as(b, &app, &app, USER).await;
        ts::register_hybrid_key_as(b, &agent, &agent, AGENT).await;
        let occ = |key: &str, class: &str| SelfAtLoginOccurrence {
            occurrence_key_id: key.to_owned(),
            device_class: class.to_owned(),
            hardware_attestation: None,
            encryption_pubkeys: None,
            transport_destinations: vec![],
            identity_key_id: None,
            occurrence_signer: Some(ts::local_signer(&e2::seed_of(key))),
            transport: None,
        };
        let out = e
            .self_at_login(SelfAtLoginInput {
                identity_key_id: identity.clone(),
                identity_signer: Some(identity_signer.clone()),
                app: occ(&app, device_class::PHONE),
                agent: occ(&agent, device_class::AGENT),
                bilateral_pair_id: uuid::Uuid::new_v4().to_string(),
                delegation_scope: None,
            })
            .await
            .expect("I4415: the login with the identity's pen completes");
        assert!(
            out.occurrences_published.contains(&app),
            "I4415: the app's bind concludes in the one call: {out:?}"
        );
        assert!(
            !out.occurrences_pending.contains(&app)
                && !out.bind_drafts.iter().any(|(k, _)| k == &app),
            "I4415: nothing of the app's bind is pending or drafted: {out:?}"
        );
        let rows = d.list_identity_occurrences_for(&identity).await.unwrap();
        let signed: Vec<String> = d
            .list_signed_identity_occurrences_for(&identity)
            .await
            .unwrap()
            .into_iter()
            .map(|o| o.identity_occurrence.occurrence_key_id)
            .collect();
        assert!(
            rows.iter().any(|o| o.occurrence_key_id == app)
                && rows.iter().all(|o| signed.contains(&o.occurrence_key_id)),
            "I4415: the app's occurrence is its signed bind, no unsigned row: {rows:?} / {signed:?}"
        );
        assert!(
            crate::federation::replication_audience::devices_of(d, &identity)
                .await
                .unwrap()
                .iter()
                .any(|o| o.occurrence_key_id == app),
            "I4415: a device of the identity at once"
        );
        assert!(
            crate::federation::self_roster::roster_now(d, &identity)
                .await
                .unwrap()
                .contains(&app),
            "I4415: a roster seat at once"
        );
        assert!(
            crate::federation::self_roster::acts_as_steward_at(
                d,
                &identity,
                &app,
                chrono::Utc::now()
            )
            .await
            .unwrap(),
            "I4415: it acts for the identity at once"
        );
    }

    /// **I4416** (WD-fix9b; the Constitution's ruling of 2026-11-22, CC
    /// 3.3.6, CC 3.3.6.4) — **the occurrence producer by kind**, through
    /// `self_at_login` (no unsigned row on any leg):
    ///
    /// - a PERSON's first device: the genesis key IS the first device (the
    ///   app key is the identity's own), so its bind is the self pair, one
    ///   statement under one pen, and it concludes without `identity_signer`;
    /// - an UNOWNED agent: nothing is stated: it is pending, with no draft
    ///   and no occurrence row, signed or not;
    /// - the next call carrying the owner's pen RESUMES it: the owner
    ///   binding is stated, then the bind, owner-authored, and it concludes
    ///   (the agent's owner is then the identity);
    /// - a LATER device takes two statements: without the device's own pen
    ///   (no proof of possession) it waits, its parts drafted, and it is no
    ///   device of the identity; with it, it concludes.
    pub(super) async fn i4416_the_occurrence_producer_by_kind<B>(b: &B, e: &crate::Engine, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
        use crate::federation::types::device_class;
        use crate::federation::types::identity_type::{AGENT, USER};
        let d = b.as_dyn_directory();
        let identity_label = format!("i4416-id-{s}");
        let identity_signer = ts::local_signer(&identity_label);
        let identity = identity_signer.federation_id().await;
        ts::register_hybrid_key_as(b, &identity, &identity_label, USER).await;
        let (later, agent) = (
            e2::kid(&format!("i4416-later-{s}")),
            e2::kid(&format!("i4416-agent-{s}")),
        );
        ts::register_hybrid_key_as(b, &later, &later, USER).await;
        ts::register_hybrid_key_as(b, &agent, &agent, AGENT).await;
        let agent_pen = ts::local_signer(&e2::seed_of(&agent));
        let occ =
            |key: &str, class: &str, pen: Option<std::sync::Arc<crate::signing::LocalSigner>>| {
                SelfAtLoginOccurrence {
                    occurrence_key_id: key.to_owned(),
                    device_class: class.to_owned(),
                    hardware_attestation: None,
                    encryption_pubkeys: None,
                    transport_destinations: vec![],
                    identity_key_id: None,
                    occurrence_signer: pen,
                    transport: None,
                }
            };
        async fn devices_of(d: &dyn FederationDirectory, identity: &str) -> Vec<String> {
            d.list_identity_occurrences_for(identity)
                .await
                .unwrap()
                .into_iter()
                .map(|o| o.occurrence_key_id)
                .collect()
        }
        async fn rows_of(d: &dyn FederationDirectory, agent: &str) -> (usize, usize) {
            (
                d.list_identity_occurrences_for(agent).await.unwrap().len(),
                d.list_signed_identity_occurrences_for(agent)
                    .await
                    .unwrap()
                    .len(),
            )
        }

        // (1) The first device is the genesis key; the agent is unowned.
        let first = e
            .self_at_login(SelfAtLoginInput {
                identity_key_id: identity.clone(),
                identity_signer: None,
                app: occ(
                    &identity,
                    device_class::PHONE,
                    Some(identity_signer.clone()),
                ),
                agent: occ(&agent, device_class::AGENT, Some(agent_pen.clone())),
                bilateral_pair_id: uuid::Uuid::new_v4().to_string(),
                delegation_scope: None,
            })
            .await
            .expect("I4416: the first login completes");
        assert_eq!(
            first.occurrences_published,
            vec![identity.clone()],
            "I4416: the person's first device (its genesis key) concludes on one pen: {first:?}"
        );
        assert_eq!(
            first.occurrences_pending,
            vec![agent.clone()],
            "I4416: the unowned agent is pending: {first:?}"
        );
        assert!(
            first.bind_drafts.is_empty(),
            "I4416: nothing is drafted (the first device needs no other voice; the unowned \
             agent has no author): {first:?}"
        );
        assert!(
            devices_of(d, &identity).await.contains(&identity),
            "I4416: the genesis key is the identity's first device"
        );
        assert_eq!(
            rows_of(d, &agent).await,
            (0, 0),
            "I4416: an unowned agent has no occurrence"
        );

        // (2) The next call carries the owner's pen: the agent resumes. A
        // later device arrives without its own pen.
        tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        let second = e
            .self_at_login(SelfAtLoginInput {
                identity_key_id: identity.clone(),
                identity_signer: Some(identity_signer.clone()),
                app: occ(&later, device_class::LAPTOP, None),
                agent: occ(&agent, device_class::AGENT, Some(agent_pen.clone())),
                bilateral_pair_id: uuid::Uuid::new_v4().to_string(),
                delegation_scope: None,
            })
            .await
            .expect("I4416: the second login completes");
        assert!(
            second.occurrences_published.contains(&agent),
            "I4416: with the owner's pen the agent's bind concludes: {second:?}"
        );
        assert_eq!(
            crate::federation::admission::agent_owner_of(
                d,
                &agent,
                u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap()
            )
            .await
            .unwrap()
            .as_deref(),
            Some(identity.as_str()),
            "I4416: the owner binding was stated first: the agent's owner is the identity"
        );
        let (agent_local, agent_signed) = rows_of(d, &agent).await;
        assert!(
            agent_local >= 1 && agent_signed >= 1,
            "I4416: the owned agent's occurrence is its signed bind"
        );
        assert!(
            second.occurrences_pending.contains(&later)
                && !second.occurrences_published.contains(&later),
            "I4416: the later device waits for its own statement: {second:?}"
        );
        assert!(
            second.bind_drafts.iter().any(|(k, _)| k == &later),
            "I4416: the later device's parts are drafted: {second:?}"
        );
        assert!(
            !devices_of(d, &identity).await.contains(&later),
            "I4416: no proof of possession, no device"
        );

        // (3) With the later device's own pen: two statements, it concludes.
        tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        let third = e
            .self_at_login(SelfAtLoginInput {
                identity_key_id: identity.clone(),
                identity_signer: Some(identity_signer.clone()),
                app: occ(
                    &later,
                    device_class::LAPTOP,
                    Some(ts::local_signer(&e2::seed_of(&later))),
                ),
                agent: occ(&agent, device_class::AGENT, Some(agent_pen.clone())),
                bilateral_pair_id: uuid::Uuid::new_v4().to_string(),
                delegation_scope: None,
            })
            .await
            .expect("I4416: the third login completes");
        assert!(
            third.occurrences_published.contains(&later),
            "I4416: the later device concludes on its two statements: {third:?}"
        );
        assert!(
            devices_of(d, &identity).await.contains(&later),
            "I4416: the later device is a device of the identity"
        );
    }

    /// **I4411** — a restart between admission and descent descends at open.
    /// Node B takes the feed through a directory wrapper that does not carry
    /// the bytes plane (the generated `FaultInjectingDirectory` forwards no
    /// `withdrawn_bytes_evictor`), withdrawal first, then a copy of the row:
    /// the door's own descent step records the descent and stops at
    /// `retraction_inadmissible` (the row and its statements deleted, the
    /// bytes not), unfinalized: what a crash mid-descent leaves. A fresh Engine on the
    /// same store, opened (`settle_at_open`, as every open runs it), finishes
    /// it: the bytes are gone and the descent finalized. No sweep runs.
    pub(super) async fn i4411_a_restart_finishes_the_descent_at_open<B>(
        a: (&B, &crate::Engine),
        bnode: (&B, &crate::Engine, std::sync::Arc<dyn FederationDirectory>),
        s: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let (ba, ea) = a;
        let (bb, eb, b_arc) = bnode;
        let da = ba.as_dyn_directory();
        let what = "I4411";
        let case = wd_case(ba, bb, s).await;
        let wid = wd_withdraw(ba, ea, &case, what).await;
        let double = crate::federation::directory_double::FaultInjectingDirectory::new(b_arc);
        assert!(
            FederationDirectory::withdrawn_bytes_evictor(&double).is_none(),
            "I4411 premise: the wrapper carries no bytes plane"
        );
        for st in served_feed(da).await {
            let _ = e2::put_statement(&double, &st).await;
        }
        let _ = e2::put_statement(&double, &case.late_copy).await;
        let db = bb.as_dyn_directory();
        assert!(
            db.get_attestation(&wid).await.expect("reads").is_some(),
            "I4411 premise: the row's arrival stamped the withdrawal at B"
        );
        // The door's descent deleted the row and its statements, then could
        // not evict the bytes: recorded, not finalized.
        let notice = crate::federation::subject_erasure::descent_notice_id(&wid, &case.id)
            .expect("the notice id");
        assert!(
            db.purge_execution(&notice)
                .await
                .expect("reads")
                .is_some_and(|x| x.finalized_at.is_none()),
            "I4411 premise: the descent is recorded and unfinished"
        );
        assert!(
            bb.has_blob(&case.sha).await.expect("reads"),
            "I4411 premise: the bytes stay"
        );
        // The restart: a fresh Engine on the same store, opened.
        let restarted = crate::Engine::from_shared(eb.backend().clone(), eb.signer().clone());
        restarted.settle_at_open().await;
        assert!(
            db.get_attestation(&case.id).await.expect("reads").is_none(),
            "I4411: the row is gone"
        );
        assert!(
            db.purge_execution(&notice)
                .await
                .expect("reads")
                .is_some_and(|x| x.finalized_at.is_some()),
            "I4411: the open finished the descent"
        );
        assert!(
            !bb.has_blob(&case.sha).await.expect("reads"),
            "I4411: and B's copy of the bytes"
        );
        assert!(
            matches!(
                restarted.held_row_state(&case.id).await.expect("reads"),
                HeldRowState::Withdrawn { .. }
            ),
            "I4411: Withdrawn"
        );
        // Idempotent: a second open descends nothing more and errors nothing.
        assert_eq!(
            restarted
                .descend_withdrawn_content_pending()
                .await
                .expect("the pass runs"),
            0,
            "I4411: a second pass descends nothing"
        );
    }
}

/// **I4406** (unit).
#[cfg(test)]
mod unit {
    use crate::federation::withdrawn_content::{
        descending_rules_sql, disposition, family_descends, rule_descends, shape_of_family_id,
        Disposition, FamilyShape, KeepPolicy, NodeRelation,
    };

    #[test]
    fn i4406_the_rule_table_and_the_switch() {
        let descends: Vec<u8> = (0..=5).filter(|r| rule_descends(*r)).collect();
        assert_eq!(
            descends,
            vec![1, 2, 3, 4],
            "I4406: rules 1–4 descend; 0 and 5 do not"
        );
        assert_eq!(
            descending_rules_sql(),
            "1, 2, 3, 4",
            "I4406: the SQL reads the same table"
        );
        let off = KeepPolicy::default();
        let on = KeepPolicy {
            signer_keeps: true,
            named_party_keeps: true,
        };
        for r in [
            NodeRelation::SignersOwnNode,
            NodeRelation::NamedPartysOwnNode,
            NodeRelation::OtherHolder,
        ] {
            for rule in 1..=4 {
                assert_eq!(
                    disposition(r, rule, off),
                    Disposition::Descend,
                    "I4406: {r:?}"
                );
            }
        }
        // Opted in: the signer's node keeps; a named party keeps only what
        // the SIGNER withdrew (rule 1, or rule 4 for the signer).
        assert_eq!(
            disposition(NodeRelation::SignersOwnNode, 2, on),
            Disposition::KeepAtSelf
        );
        for (rule, want) in [
            (1, Disposition::KeepAtSelf),
            (2, Disposition::Descend),
            (3, Disposition::Descend),
            (4, Disposition::KeepAtSelf),
        ] {
            assert_eq!(
                disposition(NodeRelation::NamedPartysOwnNode, rule, on),
                want,
                "rule {rule}"
            );
        }
        assert_eq!(
            disposition(NodeRelation::OtherHolder, 1, on),
            Disposition::Descend
        );
    }

    #[test]
    fn i4406_the_shape_table_as_constitution_states_it() {
        // v62.0.0 (FS-step1) — read from the one family table
        // (`family_model.json` `shape`), no longer a hand-derived list.
        let rows = crate::federation::namespace::family_table::table().rows();
        let count = |k: FamilyShape| rows.iter().filter(|r| r.shape == k).count();
        assert_eq!(
            [
                count(FamilyShape::Claim),
                count(FamilyShape::Content),
                count(FamilyShape::Consent),
                count(FamilyShape::Door),
                count(FamilyShape::ConsentDoor),
                count(FamilyShape::NoneFits),
            ],
            [114, 24, 16, 25, 7, 3],
            "I4406: the shapes of the family model"
        );
        let id = ciris_verify_core::namespace_match::family_id;
        assert_eq!(
            shape_of_family_id(&id("chat:*")),
            Some(FamilyShape::Content)
        );
        assert_eq!(
            shape_of_family_id(&id("file:{version}")),
            Some(FamilyShape::Content)
        );
        assert_eq!(
            shape_of_family_id(&id("membership:{stage}")),
            Some(FamilyShape::ConsentDoor)
        );
        assert_eq!(
            shape_of_family_id(&id("self:delegates_to")),
            Some(FamilyShape::NoneFits)
        );
        // Content and claims descend; structure and a shapeless family are
        // kept; a family the table does not name is kept.
        for (prefix, descends) in [
            ("chat:*", true),
            ("file:{version}", true),
            ("system:*", true),
            ("membership:{stage}", false),
            ("key:record", false),
            ("trust:blessing", false),
            ("self:delegates_to", false),
        ] {
            assert_eq!(family_descends(&id(prefix)), descends, "I4406: {prefix}");
        }
        assert!(
            !family_descends("zz:.probe"),
            "I4406: an unknown family is kept"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    use super::bodies as b;

    macro_rules! runners {
        ($m:ident, $fresh:expr) => {
            mod $m {
                use super::b;
                use crate::federation::FederationDirectory as _;
                #[tokio::test]
                async fn i4400() {
                    let Some((e, s)) = $fresh("i4400").await else {
                        return;
                    };
                    Box::pin(b::i4400_the_author_withdraws(&*s, &e, &b::suffix())).await;
                }
                #[tokio::test]
                async fn i4401() {
                    let (Some((ea, sa)), Some((eb, sb))) =
                        ($fresh("a-i4401").await, $fresh("b-i4401").await)
                    else {
                        return;
                    };
                    Box::pin(b::i4401_a_person_subject_withdraws_and_a_peer_converges(
                        (&*sa, &ea),
                        (&*sb, &eb),
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4402() {
                    let Some((_e, s)) = $fresh("i4402").await else {
                        return;
                    };
                    Box::pin(b::i4402_a_claimed_basis_lifts_nothing(&*s, &b::suffix())).await;
                }
                #[tokio::test]
                async fn i4403() {
                    let (Some((ea, sa)), Some((eb, sb))) =
                        ($fresh("a-i4403").await, $fresh("b-i4403").await)
                    else {
                        return;
                    };
                    Box::pin(b::i4403_a_cited_row_does_not_descend(
                        (&*sa, &ea),
                        (&*sb, &eb),
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4404() {
                    let Some((e, s)) = $fresh("i4404").await else {
                        return;
                    };
                    let b_arc: std::sync::Arc<dyn crate::federation::FederationDirectory> =
                        s.clone();
                    Box::pin(b::i4404_the_sweep_is_resumable(
                        &*s,
                        &e,
                        b_arc,
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4408() {
                    let Some((_e, s)) = $fresh("i4408").await else {
                        return;
                    };
                    Box::pin(b::i4408_the_keep_asks_the_nodes_owner(
                        s.as_dyn_directory(),
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4409_engine_row_first() {
                    let (Some((ea, sa)), Some((eb, sb))) = (
                        $fresh("a-i4409_engine_row_first").await,
                        $fresh("b-i4409_engine_row_first").await,
                    ) else {
                        return;
                    };
                    let b_arc: std::sync::Arc<dyn crate::federation::FederationDirectory> =
                        sb.clone();
                    Box::pin(b::i4409_descent_at_every_door(
                        (&*sa, &ea),
                        (&*sb, &eb, b_arc),
                        b::Door::Engine,
                        false,
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4409_engine_withdrawal_first() {
                    let (Some((ea, sa)), Some((eb, sb))) = (
                        $fresh("a-i4409_engine_withdrawal_first").await,
                        $fresh("b-i4409_engine_withdrawal_first").await,
                    ) else {
                        return;
                    };
                    let b_arc: std::sync::Arc<dyn crate::federation::FederationDirectory> =
                        sb.clone();
                    Box::pin(b::i4409_descent_at_every_door(
                        (&*sa, &ea),
                        (&*sb, &eb, b_arc),
                        b::Door::Engine,
                        true,
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4409_directory_row_first() {
                    let (Some((ea, sa)), Some((eb, sb))) = (
                        $fresh("a-i4409_directory_row_first").await,
                        $fresh("b-i4409_directory_row_first").await,
                    ) else {
                        return;
                    };
                    let b_arc: std::sync::Arc<dyn crate::federation::FederationDirectory> =
                        sb.clone();
                    Box::pin(b::i4409_descent_at_every_door(
                        (&*sa, &ea),
                        (&*sb, &eb, b_arc),
                        b::Door::Directory,
                        false,
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4409_directory_withdrawal_first() {
                    let (Some((ea, sa)), Some((eb, sb))) = (
                        $fresh("a-i4409_directory_withdrawal_first").await,
                        $fresh("b-i4409_directory_withdrawal_first").await,
                    ) else {
                        return;
                    };
                    let b_arc: std::sync::Arc<dyn crate::federation::FederationDirectory> =
                        sb.clone();
                    Box::pin(b::i4409_descent_at_every_door(
                        (&*sa, &ea),
                        (&*sb, &eb, b_arc),
                        b::Door::Directory,
                        true,
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4409_capsule_row_first() {
                    let (Some((ea, sa)), Some((eb, sb))) = (
                        $fresh("a-i4409_capsule_row_first").await,
                        $fresh("b-i4409_capsule_row_first").await,
                    ) else {
                        return;
                    };
                    let b_arc: std::sync::Arc<dyn crate::federation::FederationDirectory> =
                        sb.clone();
                    Box::pin(b::i4409_descent_at_every_door(
                        (&*sa, &ea),
                        (&*sb, &eb, b_arc),
                        b::Door::Capsule,
                        false,
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4409_capsule_withdrawal_first() {
                    let (Some((ea, sa)), Some((eb, sb))) = (
                        $fresh("a-i4409_capsule_withdrawal_first").await,
                        $fresh("b-i4409_capsule_withdrawal_first").await,
                    ) else {
                        return;
                    };
                    let b_arc: std::sync::Arc<dyn crate::federation::FederationDirectory> =
                        sb.clone();
                    Box::pin(b::i4409_descent_at_every_door(
                        (&*sa, &ea),
                        (&*sb, &eb, b_arc),
                        b::Door::Capsule,
                        true,
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4409_json_row_first() {
                    let (Some((ea, sa)), Some((eb, sb))) = (
                        $fresh("a-i4409_json_row_first").await,
                        $fresh("b-i4409_json_row_first").await,
                    ) else {
                        return;
                    };
                    let b_arc: std::sync::Arc<dyn crate::federation::FederationDirectory> =
                        sb.clone();
                    Box::pin(b::i4409_descent_at_every_door(
                        (&*sa, &ea),
                        (&*sb, &eb, b_arc),
                        b::Door::Json,
                        false,
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4409_json_withdrawal_first() {
                    let (Some((ea, sa)), Some((eb, sb))) = (
                        $fresh("a-i4409_json_withdrawal_first").await,
                        $fresh("b-i4409_json_withdrawal_first").await,
                    ) else {
                        return;
                    };
                    let b_arc: std::sync::Arc<dyn crate::federation::FederationDirectory> =
                        sb.clone();
                    Box::pin(b::i4409_descent_at_every_door(
                        (&*sa, &ea),
                        (&*sb, &eb, b_arc),
                        b::Door::Json,
                        true,
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4409_jsoncapsule_row_first() {
                    let (Some((ea, sa)), Some((eb, sb))) = (
                        $fresh("a-i4409_jsoncapsule_row_first").await,
                        $fresh("b-i4409_jsoncapsule_row_first").await,
                    ) else {
                        return;
                    };
                    let b_arc: std::sync::Arc<dyn crate::federation::FederationDirectory> =
                        sb.clone();
                    Box::pin(b::i4409_descent_at_every_door(
                        (&*sa, &ea),
                        (&*sb, &eb, b_arc),
                        b::Door::JsonCapsule,
                        false,
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4409_jsoncapsule_withdrawal_first() {
                    let (Some((ea, sa)), Some((eb, sb))) = (
                        $fresh("a-i4409_jsoncapsule_withdrawal_first").await,
                        $fresh("b-i4409_jsoncapsule_withdrawal_first").await,
                    ) else {
                        return;
                    };
                    let b_arc: std::sync::Arc<dyn crate::federation::FederationDirectory> =
                        sb.clone();
                    Box::pin(b::i4409_descent_at_every_door(
                        (&*sa, &ea),
                        (&*sb, &eb, b_arc),
                        b::Door::JsonCapsule,
                        true,
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4415() {
                    let Some((e, s)) = $fresh("i4415").await else {
                        return;
                    };
                    Box::pin(b::i4415_a_login_with_the_identity_pen_concludes_at_once(
                        &*s,
                        &e,
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4416() {
                    let Some((e, s)) = $fresh("i4416").await else {
                        return;
                    };
                    Box::pin(b::i4416_the_occurrence_producer_by_kind(
                        &*s,
                        &e,
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4414() {
                    let Some((e, s)) = $fresh("i4414").await else {
                        return;
                    };
                    Box::pin(b::i4414_a_first_login_writes_no_unsigned_occurrence(
                        &*s,
                        &e,
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4410() {
                    let Some((e, s)) = $fresh("i4410").await else {
                        return;
                    };
                    Box::pin(b::i4410_a_purged_withdrawal_leaves_the_descent_standing(
                        &*s,
                        &e,
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4411() {
                    let (Some((ea, sa)), Some((eb, sb))) =
                        ($fresh("a-i4411").await, $fresh("b-i4411").await)
                    else {
                        return;
                    };
                    let b_arc: std::sync::Arc<dyn crate::federation::FederationDirectory> =
                        sb.clone();
                    Box::pin(b::i4411_a_restart_finishes_the_descent_at_open(
                        (&*sa, &ea),
                        (&*sb, &eb, b_arc),
                        &b::suffix(),
                    ))
                    .await;
                }
                #[tokio::test]
                async fn i4405() {
                    let Some((e, s)) = $fresh("i4405").await else {
                        return;
                    };
                    Box::pin(b::i4405_structure_is_kept_a_claim_descends(
                        &*s,
                        &e,
                        &b::suffix(),
                    ))
                    .await;
                }
            }
        };
    }

    #[cfg(feature = "sqlite")]
    async fn sqlite(
        seed: &str,
    ) -> Option<(crate::Engine, std::sync::Arc<crate::store::SqliteBackend>)> {
        let signer = crate::federation::tier_ingest::test_support::local_signer(seed);
        let e = crate::Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("sqlite");
        let s = e.sqlite_backend().expect("sqlite").clone();
        // WD-fix10 (pass 5 reds) — the node is ROOTED: a rootless node
        // withholds federation-tier rows from a third party
        // (`edition2::serve::SERVE_WAITS_FOR_ROOTED`, CC 5.3.4), so a peer
        // fed from it held nothing and every two-node premise failed.
        crate::federation::edition2::serve_wait_invariants::test_support::root_this_node(&*s).await;
        Some((e, s))
    }

    #[cfg(feature = "postgres")]
    async fn postgres(
        seed: &str,
    ) -> Option<(crate::Engine, std::sync::Arc<crate::store::PostgresBackend>)> {
        let dsn = crate::test_pg::isolated_dsn()?;
        let signer = crate::federation::tier_ingest::test_support::local_signer(seed);
        let e = crate::Engine::with_signer(signer, &dsn)
            .await
            .expect("postgres");
        let s = e.postgres_backend().expect("postgres").clone();
        // WD-fix10 — rooted, as on sqlite.
        crate::federation::edition2::serve_wait_invariants::test_support::root_this_node(&*s).await;
        Some((e, s))
    }

    #[cfg(feature = "sqlite")]
    runners!(sqlite_lane, super::sqlite);
    #[cfg(feature = "postgres")]
    runners!(postgres_lane, super::postgres);
}
