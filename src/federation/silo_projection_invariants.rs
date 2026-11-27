//! v57.0.0 (CIRISPersist#988 items 2, 3; CLM-silo-projection-rebuildable) —
//! **I960 / I961: each moved silo is its rows' rebuild, on every backend.**
//!
//! - **I960 (`hard_case_events`)** — the hard_case door
//!   (`record_hard_case`: an observed condition, an attributed admin action, a
//!   re-record of the same event) and an in-transaction emitter (the peer
//!   removal's `admin_action:peer_removal`) each leave a `hard_case:{kind}:v1`
//!   row on the plane, attested by the node key; then the from-rows rebuild
//!   of `hard_case_events` is byte-equal to the live table
//!   ([`check_projection_rebuild`](crate::federation::silo_projection::check_projection_rebuild)).
//!   The row is unpurgeable (the accountability-record family). (v60.0.0:
//!   it replicates; I1165 witnesses the crossing and the peer's copy.)
//! - **I961 (`detection_events`)** — two detections stated by a conferred
//!   detector (v62: `detection_row::state_detection`; the earlier
//!   `put_detection_event` door is deleted), an idempotent re-statement and an
//!   unconferred one held, then the DSAR erasure of one
//!   detection's trace: its signed row is hard-deleted under a tombstone
//!   citing the producer's `withdraws` (never rewritten), and the rebuild is
//!   byte-equal again.
//!
//! - **I962 (the attester refusal, lead ruling 3)** — with no node key an
//!   erasure, a peer removal and `record_hard_case` are each refused with the
//!   typed `HardCaseAttesterUnavailable` (kind
//!   `hard_case::refusal::ATTESTER_UNAVAILABLE`) and NOTHING moves; with the
//!   node key held the same erasure SUCCEEDS, records its
//!   `hard_case:trace_erasure:v1` row, and the projection is its rebuild.
//! - **I963 (the legacy rehome)** — DELETED in v62.0.0 (P8-fix7): it
//!   seeded pre-v57 silo rows (no backing row, a v56 node's writes) and
//!   witnessed their rehome onto the plane. A v62 node reads nothing from an
//!   earlier store (CC 1.0-rc20 "nothing carries, clean mesh"; V300 refuses
//!   any history below 300 and `store::edition_upgrade` deletes such a
//!   store), so no v62 store can hold the rows it rehomes, and a rehomed row
//!   is an earlier-form row (attested by a hybrid key, no statement) the
//!   edition-2 doors refuse.
//!
//! - **I964 (the DSAR erasure of a detection, lead ruling on the DSAR
//!   path)** — on both DSAR doors, the erased trace's signed detection row
//!   is HARD-DELETED in the erasure's transaction and NO `detection_events`
//!   row remains for it (no remnant: an opaque consumer payload must stay
//!   erasable); v58.0.0 (#1094 item 2) — erased under its producer's
//!   rule-1 `withdraws` (CC 4.5.3), its tombstone header
//!   cites that withdraws, is finalized and is SERVED; a re-put is refused
//!   TOMBSTONED; the counter counts it
//!   (and, on sqlite and postgres, a pre-v57 row rehomed and erased with
//!   it); the gate holds and a re-run changes nothing.
//!
//! Each runner then TAMPERS with the live table (one column of one row) and
//! asserts the gate goes red: a witness that cannot fail is a report.
//!
//! v62.0.0 (v62 P8-fix7, CP2) — I961 and I964 are EDITION 2 on sqlite and
//! postgres, no earlier-form scope: each detection is its detector's own
//! `detection:{detector}` statement (`detection_row::state_detection`), the
//! detector an `agent` key holding `infra:detect` conferred by a root this
//! node accepts (E7's `subject_erasure_invariants` fixtures), the row id
//! node-computed; the DSAR erasure cites the producer's own `withdraws`
//! statement. The earlier-form properties are gone with the door that had
//! them: a detection id is no longer the row id, so "different bytes under a
//! held detection_id conflict" has no edition-2 statement (different bytes
//! are a different row), and a pre-v57 detection rides no erasure (I963).

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::attestation_admit::AttestationStore;
    use crate::federation::hard_case::{self, HardCaseEvent};
    use crate::federation::silo_projection::{check_projection_rebuild, SiloProjection};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type;
    use crate::federation::FederationDirectory;

    /// Register `node` as this backend's node key (the runner sets
    /// `set_node_key_id`, an inherent method of each backend).
    pub(crate) async fn register_node<B: FederationDirectory>(b: &B, node: &str) {
        ts::register_hybrid_key_as(b, node, node, identity_type::NODE).await;
    }

    fn event(id: &str, kind: &str, detail: serde_json::Value) -> HardCaseEvent {
        HardCaseEvent {
            event_id: id.to_owned(),
            kind: kind.to_owned(),
            target_key_id: Some(format!("{id}-target")),
            subject_key_id: Some(format!("{id}-subject")),
            detail,
            emitted_at: chrono::Utc::now(),
            emitter_key_id: String::new(),
        }
    }

    /// I960 — the writers, then the gate. Returns the live row count.
    pub(crate) async fn i960_hard_case<B>(b: &B, node: &str, tag: &str) -> usize
    where
        B: AttestationStore,
    {
        let sla = event(
            &format!("{tag}-sla"),
            hard_case::kind::CONSENT_SLA_BREACH,
            serde_json::json!({"sla_days": 30, "ratio": 1.5, "nested": {"z": 1, "a": [1, 2]}}),
        );
        b.record_hard_case(sla.clone())
            .await
            .expect("I960: an observed condition records");
        // Re-recording the same event is a no-op (the row id derives from it).
        b.record_hard_case(sla.clone())
            .await
            .expect("I960: a re-record is a no-op");
        let admin = hard_case::admin_action_event(
            hard_case::admin_op::QUARANTINE,
            &format!("{tag}-bad"),
            Some(node),
            "att-delegation-1",
            "sustained spam",
            chrono::Utc::now(),
        );
        b.record_hard_case(admin.clone())
            .await
            .expect("I960: an attributed act records");
        // The in-transaction emitter: a soft peer removal announces itself.
        let peer = format!("{tag}-peer");
        b.add_peer_record(&peer, "AAAA", identity_type::AGENT, None)
            .await
            .expect("I960: a peer to remove");
        b.remove_peer_record(&peer, false, "I960 removal", None)
            .await
            .expect("I960: the removal and its record");

        let rows = b
            .list_hard_case_events(hard_case::HardCaseFilter::default())
            .await
            .expect("I960: list");
        let mine: Vec<&HardCaseEvent> = rows
            .iter()
            .filter(|e| {
                e.event_id.starts_with(tag)
                    || e.target_key_id
                        .as_deref()
                        .is_some_and(|t| t.starts_with(tag))
            })
            .collect();
        assert_eq!(
            mine.len(),
            3,
            "I960: three events recorded once each: {mine:?}"
        );

        // Each is a local-tier row on the plane, attested by the node key.
        for id in [&sla.event_id, &admin.event_id] {
            let row = b
                .get_attestation(&hard_case::hard_case_attestation_id(id))
                .await
                .expect("I960: get")
                .expect("I960: the event is a row");
            assert_eq!(row.attesting_key_id, node, "I960: attester = the node key");
            assert_eq!(row.tier, "local", "I960: the door writes the local tier");
            assert_eq!(row.attestation_type, "scores");
            assert_eq!(
                hard_case::project_hard_case_row(&row).map(|e| e.event_id),
                Some(id.clone()),
                "I960: the row projects to its event"
            );
            // Unpurgeable: the accountability-record family refuses it.
            assert!(
                crate::federation::migration::check_purge_admission(&row).is_err(),
                "I960: a hard_case row is the accountability record"
            );
        }
        let rebuild = check_projection_rebuild(b, SiloProjection::HardCaseEvents)
            .await
            .expect("I960: hard_case_events is its rows' rebuild");
        assert!(rebuild.live.len() >= 3, "I960: the gate compared rows");
        rebuild.live.len()
    }

    /// v62.0.0 (P8-fix7) — the conferred detector of `tag` (E7's
    /// `detector_seed`, an `agent` key holding `infra:detect` from `tag`'s
    /// root, which this node accepts: the runner set the node key first).
    /// Returns its seed.
    pub(crate) async fn conferred_detector<B>(b: &B, tag: &str) -> String
    where
        B: FederationDirectory,
    {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::subject_erasure_invariants::bodies as sub;
        let det = sub::detector_seed(tag);
        e2::put_key(b, &det, &[identity_type::AGENT]).await;
        sub::confer_detect(b, tag, &det).await;
        det
    }

    /// v62.0.0 (P8-fix7) — a held trace of `agent` on `trace`, and `det`'s
    /// detection of it, stated on edition 2: the event and its node-computed
    /// row id.
    pub(crate) async fn stated<B>(
        b: &B,
        det: &str,
        agent: &str,
        trace: &str,
    ) -> (crate::derived::DetectionEvent, String)
    where
        B: AttestationStore + crate::store::Backend,
    {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::subject_erasure_invariants::bodies as sub;
        b.insert_trace_events_batch(&[trace_row(trace, agent)])
            .await
            .unwrap();
        let mut ev = sub::detection(trace, &e2::kid(det));
        ev.ts = crate::federation::admission::truncate_to_substrate_resolution(
            chrono::Utc::now() - chrono::Duration::minutes(2),
        );
        let id = crate::derived::detection_row::state_detection(b, &ts::local_signer(det), &ev)
            .await
            .unwrap_or_else(|e| panic!("the conferred detector states its detection: {e}"));
        (ev, id)
    }

    /// v62.0.0 (P8-fix8) — the statement a held row carries (its signed
    /// bytes), read BEFORE an erasure deletes the row.
    pub(crate) async fn statement_of<B>(b: &B, row_id: &str) -> Vec<u8>
    where
        B: FederationDirectory,
    {
        let row = b
            .get_attestation(row_id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("row {row_id} is held"));
        crate::federation::edition2::emit::carried_statement(&row)
            .unwrap_or_else(|| panic!("row {row_id} carries its statement"))
    }

    /// v62.0.0 (P8-fix8) — **the tombstone refuses the row's re-admission**:
    /// the erased row's OWN statement, re-offered byte for byte through the
    /// statement door (the same row id: what a replica would bring back), is
    /// refused `purge_tombstoned` (`steward_purge::token::TOMBSTONED`, the
    /// attestation plan's `refuse_if_tombstoned_attestation`), and the row
    /// stays gone. Pinned to the token, never `is_err`: a broken fixture
    /// must not pass for a tombstone.
    async fn assert_reoffer_tombstoned<B>(b: &B, statement: &[u8], row_id: &str, what: &str)
    where
        B: FederationDirectory,
    {
        use crate::federation::steward_purge::token::TOMBSTONED;
        let again = crate::federation::edition2::ingest::put_statement(
            b,
            statement,
            None,
            crate::federation::edition2::ingest::INGEST_TIER,
        )
        .await;
        match &again {
            Err(crate::federation::Error::PurgeRefused { token, .. }) if *token == TOMBSTONED => {}
            other => panic!(
                "{what}: the erased row's statement re-offered is refused {TOMBSTONED}: {other:?}"
            ),
        }
        assert!(
            b.get_attestation(row_id).await.unwrap().is_none(),
            "{what}: nothing was re-admitted"
        );
    }

    /// The live projection of `ev` (its trace's events), by detection id.
    async fn projected<B>(b: &B, ev: &crate::derived::DetectionEvent) -> Vec<uuid::Uuid>
    where
        B: crate::derived::DerivedSchema,
    {
        b.get_detection_events(crate::derived::EventFilter {
            trace_id: Some(ev.trace_id.clone()),
            ..Default::default()
        })
        .await
        .expect("read the projection")
        .into_iter()
        .map(|e| e.detection_id)
        .collect()
    }

    /// I961 — the writers (no erasure), then the gate. Returns the two
    /// detections (event, row id) the runner erases the first of, and the
    /// detector's seed (the producer that states the erasure's withdraws).
    ///
    /// v62.0.0 (P8-fix7) — edition 2: an identical re-statement is the same
    /// row (idempotent); a detector with no `infra:detect` conferral is
    /// refused (standing is the conferral plane's, never the key's type).
    #[allow(clippy::type_complexity)]
    pub(crate) async fn i961_detection<B>(
        b: &B,
        tag: &str,
    ) -> (
        (crate::derived::DetectionEvent, String),
        (crate::derived::DetectionEvent, String),
        String,
    )
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend,
    {
        use crate::federation::edition2::fixture_switch as e2;
        let det = conferred_detector(b, tag).await;
        let (a, a_row) = stated(
            b,
            &det,
            &format!("{tag}-agent-h"),
            &format!("{tag}-trace-a"),
        )
        .await;
        let (c, c_row) = stated(
            b,
            &det,
            &format!("{tag}-agent-c"),
            &format!("{tag}-trace-c"),
        )
        .await;
        assert_ne!(a_row, c_row, "I961: two detections, two rows");
        let again = crate::derived::detection_row::state_detection(b, &ts::local_signer(&det), &a)
            .await
            .expect("I961: an identical re-statement is admitted");
        assert_eq!(again, a_row, "I961: the same statement is the same row");
        // A detector that is not one: an agent key with no conferral.
        let rogue = format!("{tag}-rogue");
        e2::put_key(b, &rogue, &[identity_type::AGENT]).await;
        b.insert_trace_events_batch(&[trace_row(
            &format!("{tag}-trace-x"),
            &format!("{tag}-agent-x"),
        )])
        .await
        .unwrap();
        let mut x = crate::federation::subject_erasure_invariants::bodies::detection(
            &format!("{tag}-trace-x"),
            &e2::kid(&rogue),
        );
        x.ts = a.ts;
        // v62.0.0 (P8-fix8) — an unconferred emitter of a reserved family is
        // a FOLD condition (CC 2.7.3: G0/GC1 hold it, they never refuse it):
        // the statement is kept and the row HELD under
        // `reserved_family_unseated` (D4), so it is neither seated nor
        // projected. Pinned to the reason, never `is_err`.
        let x_row =
            crate::derived::detection_row::state_detection(b, &ts::local_signer(&rogue), &x)
                .await
                .expect("I961: an unconferred detection is held, not an error");
        assert!(
            b.get_attestation(&x_row).await.unwrap().is_none(),
            "I961: only a conferred detector's detection is seated"
        );
        let held = crate::federation::edition2::fold::why_held(
            b,
            &crate::federation::edition2::names::RowId(
                <[u8; 32]>::try_from(hex::decode(&x_row).unwrap().as_slice()).unwrap(),
            ),
        )
        .await
        .unwrap()
        .expect("I961: the unconferred detection is held");
        assert_eq!(
            held.reason,
            crate::federation::edition2::fold::reason::gc1::RESERVED_FAMILY_UNSEATED,
            "I961: held for the missing infra:detect conferral: {held:?}"
        );
        assert!(
            projected(b, &x).await.is_empty(),
            "I961: the held detection projects nothing"
        );
        let row = b
            .get_attestation(&a_row)
            .await
            .expect("I961: get")
            .expect("I961: the detection is a row");
        assert_eq!(
            row.attesting_key_id,
            e2::kid(&det),
            "I961: attester = the detector"
        );
        // The gate first, so a writer that moved a column is caught by it
        // before the read-back below sees the same column.
        check_projection_rebuild(b, SiloProjection::DetectionEvents)
            .await
            .expect("I961: detection_events is its rows' rebuild");
        assert_eq!(
            projected(b, &a).await,
            vec![a.detection_id],
            "I961: the projection reads back the event"
        );
        ((a, a_row), (c, c_row), det)
    }

    /// I961, after the runner ran the DSAR erasure of `erased`'s trace (its
    /// producer's `withdraws` stated first): the erased detection's signed
    /// row was HARD-DELETED in the erasure's transaction (never rewritten),
    /// its projection row left with it, and a purge tombstone whose header
    /// cites the producer's `withdraws` refuses its re-admission. The other
    /// detection is untouched and the table is its rows' rebuild.
    pub(crate) async fn i961_after_erasure<B>(
        b: &B,
        det: &str,
        erased: &(crate::derived::DetectionEvent, String),
        erased_statement: &[u8],
        kept: &(crate::derived::DetectionEvent, String),
    ) where
        B: AttestationStore + crate::derived::DerivedSchema,
    {
        use crate::federation::edition2::fixture_switch as e2;
        let (erased, erased_row) = (&erased.0, &erased.1);
        assert!(
            b.get_attestation(erased_row).await.unwrap().is_none(),
            "I961: the erased detection's signed row is hard-deleted, not rewritten"
        );
        assert!(
            projected(b, erased).await.is_empty(),
            "I961: the erased detection is not returned"
        );
        assert_eq!(
            projected(b, &kept.0).await,
            vec![kept.0.detection_id],
            "I961: the other detection is untouched"
        );
        assert!(
            b.get_attestation(&kept.1).await.unwrap().is_some(),
            "I961: the other detection's row is held"
        );
        let notice = b
            .purge_tombstoned("attestation", erased_row)
            .await
            .unwrap()
            .expect("I961: the erased row is tombstoned");
        let header = b
            .purge_execution(&notice)
            .await
            .unwrap()
            .expect("I961: the tombstone's header");
        assert_eq!(
            header.legal_basis,
            crate::federation::subject_erasure::WITHDRAWS_AUTHORITY
        );
        assert!(header.finalized_at.is_some(), "I961: finalized at once");
        assert!(
            b.list_purge_executions_since(None, 100)
                .await
                .unwrap()
                .iter()
                .any(|e| e.notice_id == notice),
            "I961: the erasure's header is served"
        );
        let cited = crate::federation::subject_erasure::ErasureNotice::parse(
            &serde_json::from_str(&header.notice_jcs).unwrap(),
        )
        .expect("I961: the header cites the subject's withdraws");
        assert_eq!(&cited.target_attestation_id, erased_row);
        let withdraws = b
            .get_attestation(&cited.withdraws_attestation_id)
            .await
            .unwrap()
            .expect("I961: the cited withdraws is held");
        assert_eq!(
            withdraws.attesting_key_id,
            e2::kid(det),
            "I961: the producer"
        );
        assert_reoffer_tombstoned(b, erased_statement, erased_row, "I961").await;
        check_projection_rebuild(b, SiloProjection::DetectionEvents)
            .await
            .expect("I961: after the erasure, detection_events is its rows' rebuild");
    }

    /// I962 (no node key) — every act that must record a hard_case row is
    /// refused, typed, and nothing moves.
    pub(crate) async fn i962_refused_without_a_node_key<B>(b: &B, tag: &str)
    where
        B: AttestationStore + crate::store::Backend,
    {
        use crate::federation::hard_case::refusal;
        let agent = format!("{tag}-agent-h");
        b.insert_trace_events_batch(&[trace_row(&format!("{tag}-trace"), &agent)])
            .await
            .unwrap();
        match b.delete_traces_for_agent_id_hash(&agent).await {
            Err(e @ crate::store::Error::HardCaseAttesterUnavailable(_)) => {
                assert_eq!(e.kind(), refusal::ATTESTER_UNAVAILABLE, "I962: {e}");
            }
            other => panic!("I962: the erasure must refuse, typed, got {other:?}"),
        }
        assert_eq!(
            b.fetch_trace_events_page(0, 10, Some(&agent))
                .await
                .unwrap()
                .len(),
            1,
            "I962: the refused erasure deleted nothing"
        );
        let peer = format!("{tag}-peer");
        b.add_peer_record(&peer, "AAAA", identity_type::AGENT, None)
            .await
            .unwrap();
        let e = b
            .remove_peer_record(&peer, false, "I962", None)
            .await
            .expect_err("I962: the peer removal must refuse");
        assert_eq!(e.kind(), refusal::ATTESTER_UNAVAILABLE, "I962: {e}");
        assert!(
            b.peer_metadata_for(&peer)
                .await
                .unwrap()
                .is_some_and(|m| m.removed_at.is_none()),
            "I962: the refused removal left the peer live"
        );
        let e = b
            .record_hard_case(event(
                &format!("{tag}-x"),
                hard_case::kind::CONSENT_SLA_BREACH,
                serde_json::json!({}),
            ))
            .await
            .expect_err("I962: record_hard_case must refuse");
        assert_eq!(e.kind(), refusal::ATTESTER_UNAVAILABLE, "I962: {e}");
        assert!(
            b.list_hard_case_events(hard_case::HardCaseFilter::default())
                .await
                .unwrap()
                .is_empty(),
            "I962: nothing was recorded"
        );
    }

    /// I962 (node key held) — the same erasure succeeds and records its row.
    pub(crate) async fn i962_succeeds_with_the_node_key<B>(b: &B, node: &str, tag: &str)
    where
        B: AttestationStore + crate::store::Backend,
    {
        let agent = format!("{tag}-agent-h");
        let summary = b
            .delete_traces_for_agent_id_hash(&agent)
            .await
            .expect("I962: with a held node key the erasure succeeds");
        assert_eq!(summary.trace_events, 1, "I962: the trace was erased");
        let rows = b
            .list_hard_case_events(hard_case::HardCaseFilter {
                kind: Some(hard_case::kind::TRACE_ERASURE.to_owned()),
                since: None,
                emitter_key_id: None,
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "I962: the erasure recorded its row");
        let row = b
            .get_attestation(&hard_case::hard_case_attestation_id(&rows[0].event_id))
            .await
            .unwrap()
            .expect("I962: the record is a row");
        assert_eq!(row.attesting_key_id, node, "I962: attested by the node key");
        check_projection_rebuild(b, SiloProjection::HardCaseEvents)
            .await
            .expect("I962: hard_case_events is its rows' rebuild");
    }

    /// I964 — the DSAR erasure of a trace with a row-backed detection,
    /// then the key-scoped door (`delete_traces_for_agent`) on a second
    /// trace. v62.0.0 (P8-fix7) — edition 2: each detection is its conferred
    /// detector's statement, and each erasure cites the producer's own
    /// `withdraws` (stated first, CC 4.5.3). No pre-v57 detection rides it
    /// (I963's deletion).
    pub(crate) async fn i964_the_dsar_erasure<B>(b: &B, tag: &str)
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend + Sync,
    {
        use crate::federation::subject_erasure_invariants::bodies as sub;
        let det = conferred_detector(b, tag).await;
        let agent = format!("{tag}-agent-h");
        let trace = format!("{tag}-trace");
        let (original, row_id) = stated(b, &det, &agent, &trace).await;
        let original_statement = statement_of(b, &row_id).await;
        sub::state_producer_withdraws(b, &det, &agent, None).await;

        let summary = b.delete_traces_for_agent_id_hash(&agent).await.unwrap();
        assert_eq!(summary.detection_events_tombstoned, 1, "I964: the counter");
        assert!(
            b.get_attestation(&row_id).await.unwrap().is_none(),
            "I964: the signed row is hard-deleted"
        );
        i964_no_projection_row(b, &[original.detection_id]).await;
        let notice = b
            .purge_tombstoned("attestation", &row_id)
            .await
            .unwrap()
            .expect("I964: the erased row is tombstoned");
        let header = b
            .purge_execution(&notice)
            .await
            .unwrap()
            .expect("I964: the tombstone's header");
        assert_eq!(
            header.legal_basis,
            crate::federation::subject_erasure::WITHDRAWS_AUTHORITY
        );
        assert!(
            header.finalized_at.is_some(),
            "I964: finalized at execution"
        );
        assert_eq!(header.record_count, 1, "I964: one tombstone per row");
        assert!(
            b.list_purge_executions_since(None, 100)
                .await
                .unwrap()
                .iter()
                .any(|e| e.notice_id == notice),
            "I964: the erasure's header is served"
        );
        assert_reoffer_tombstoned(b, &original_statement, &row_id, "I964").await;
        check_projection_rebuild(b, SiloProjection::DetectionEvents)
            .await
            .expect("I964: detection_events is its rows' rebuild after the erasure");
        let again = b.delete_traces_for_agent_id_hash(&agent).await.unwrap();
        assert_eq!(
            (again.trace_events, again.detection_events_tombstoned),
            (0, 0),
            "I964: a re-run is a no-op"
        );
        check_projection_rebuild(b, SiloProjection::DetectionEvents)
            .await
            .expect("I964: still its rows' rebuild");

        // The key-scoped door erases the same way.
        let agent2 = format!("{tag}-agent-k");
        let trace2 = format!("{tag}-trace-k");
        let (second, row2) = stated(b, &det, &agent2, &trace2).await;
        let signer_key = format!("{agent2}-signer");
        sub::state_producer_withdraws(b, &det, &agent2, Some(&signer_key)).await;
        b.delete_traces_for_agent(&agent2, &signer_key, false)
            .await
            .unwrap();
        assert!(
            b.get_attestation(&row2).await.unwrap().is_none(),
            "I964: the key-scoped door hard-deletes the signed row"
        );
        i964_no_projection_row(b, &[second.detection_id]).await;
        assert!(
            b.purge_tombstoned("attestation", &row2)
                .await
                .unwrap()
                .is_some(),
            "I964: the key-scoped door tombstones it"
        );
        check_projection_rebuild(b, SiloProjection::DetectionEvents)
            .await
            .expect("I964: the rebuild after the key-scoped door");

        // v62.0.0 (P8-fix8; lead ruling: NO re-put gate after a DSAR
        // erasure) — the detector may state the same detection event again:
        // its trace is gone, so the subject resolves to nothing and the
        // re-statement is a NEW, subject-less row (another row id), the
        // detector's own new act. The tombstone protects the erased ROW (its
        // own bytes stay refused, above), never the detection id. Witnessed:
        // the new row names nobody the erasure was for.
        let subject = crate::federation::subject_erasure::agent_subject(&agent).unwrap();
        let restated =
            crate::derived::detection_row::state_detection(b, &ts::local_signer(&det), &original)
                .await
                .expect("I964: the detector's own new statement is admitted");
        assert_ne!(
            restated, row_id,
            "I964: a subject-less re-statement is another row"
        );
        let new_row = b
            .get_attestation(&restated)
            .await
            .unwrap()
            .expect("I964: the new row is seated");
        assert!(
            new_row.subject_key_ids.is_empty(),
            "I964: the new row names no subject: {:?}",
            new_row.subject_key_ids
        );
        let stored = serde_json::to_string(&new_row.attestation_envelope).unwrap();
        assert!(
            !stored.contains(&subject) && !stored.contains(&agent),
            "I964: nothing about the erased subject is stored: {stored}"
        );
        assert!(
            b.get_attestation(&row_id).await.unwrap().is_none(),
            "I964: the erased row stays gone"
        );
        check_projection_rebuild(b, SiloProjection::DetectionEvents)
            .await
            .expect("I964: the rebuild after the re-statement");
    }

    /// No live `detection_events` row (tombstoned or not) names any of `ids`.
    async fn i964_no_projection_row<B>(b: &B, ids: &[uuid::Uuid])
    where
        B: AttestationStore,
    {
        let live = check_projection_rebuild(b, SiloProjection::DetectionEvents)
            .await
            .map(|r| r.live)
            .unwrap_or_else(|e| panic!("I964: the live table: {e}"));
        for id in ids {
            assert!(
                live.iter().all(|row| !row.contains(&id.to_string())),
                "I964: no detection_events row remains for {id}"
            );
        }
    }

    /// A trace event row for `agent` on `trace`, so the erasure has something
    /// to erase.
    pub(crate) fn trace_row(trace: &str, agent: &str) -> crate::store::TraceEventRow {
        crate::store::TraceEventRow {
            trace_id: trace.to_owned(),
            thought_id: format!("{trace}-th"),
            task_id: None,
            step_point: None,
            event_type: crate::schema::ReasoningEventType::ThoughtStart,
            attempt_index: 0,
            ts: chrono::Utc::now(),
            agent_name: None,
            agent_id_hash: agent.to_owned(),
            cognitive_state: None,
            trace_level: crate::schema::TraceLevel::Detailed,
            payload: serde_json::Map::new(),
            cost_llm_calls: None,
            cost_tokens: None,
            cost_usd: None,
            signature: "sig-test".to_owned(),
            signing_key_id: format!("{agent}-signer"),
            signature_verified: true,
            verification_source: crate::store::VerificationSource::Persist,
            schema_version: "2.7.0".to_owned(),
            pii_scrubbed: true,
            original_content_hash: None,
            scrub_signature: None,
            scrub_key_id: None,
            scrub_timestamp: None,
            admitted_at: None,
            scrub_ner_ran: None,
            scrub_applied_trace_level: None,
            scrub_model_digest: None,
            agent_role: None,
            agent_template: None,
            deployment_domain: None,
            deployment_type: None,
            deployment_region: None,
            deployment_trust_mode: None,
            cohort_scope: "federation".to_string(),
            cohort_target_id: None,
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
        }
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    use super::bodies;
    use crate::federation::silo_projection::{check_projection_rebuild, SiloProjection};
    use crate::federation::subject_erasure_invariants::bodies as sub;
    use crate::store::Backend as _;

    fn tag(n: &str) -> String {
        format!("{n}-{}", uuid::Uuid::new_v4().simple())
    }

    #[cfg(feature = "sqlite")]
    async fn sqlite() -> crate::store::sqlite::SqliteBackend {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i960_sqlite() {
        let b = sqlite().await;
        let t = tag("i960s");
        let node = format!("{t}-node");
        bodies::register_node(&b, &node).await;
        // v62.0.0 (K1) — the node key is held under its edition-2 id.
        let node = crate::federation::hard_case::test_support::node_key_id_of(&node);
        b.set_node_key_id(&node);
        bodies::i960_hard_case(&b, &node, &t).await;
        // RED: one column of one live row moved.
        b.test_execute(
            "UPDATE hard_case_events SET detail = '{}' WHERE kind = 'consent_sla_breach'",
        )
        .await;
        assert!(
            check_projection_rebuild(&b, SiloProjection::HardCaseEvents)
                .await
                .is_err(),
            "I960 sqlite: a moved column is red"
        );
    }

    /// The other red: a projection row no attestation produces (an orphan).
    /// Until v60.0.0 only the retired memory backend witnessed it (#1002).
    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i960_sqlite_red_on_an_orphan_projection_row() {
        let b = sqlite().await;
        let t = tag("i960so");
        let node = format!("{t}-node");
        bodies::register_node(&b, &node).await;
        // v62.0.0 (K1) — the node key is held under its edition-2 id.
        let node = crate::federation::hard_case::test_support::node_key_id_of(&node);
        b.set_node_key_id(&node);
        bodies::i960_hard_case(&b, &node, &t).await;
        // RED: a copy of a live row under ids no row produces, planted below
        // the foreign key that keeps a door from writing one (the corruption
        // this rebuild exists to see).
        b.test_execute(&format!(
            "PRAGMA foreign_keys = OFF; \
             CREATE TEMP TABLE i960_orphan AS SELECT * FROM hard_case_events LIMIT 1; \
             UPDATE i960_orphan SET event_id = '{t}-orphan', attestation_id = '{t}-orphan'; \
             INSERT INTO hard_case_events SELECT * FROM i960_orphan; \
             PRAGMA foreign_keys = ON;"
        ))
        .await;
        assert!(
            check_projection_rebuild(&b, SiloProjection::HardCaseEvents)
                .await
                .is_err(),
            "I960 sqlite: an entry no row produces is red"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i961_sqlite() {
        let b = sqlite().await;
        let t = tag("i961s");
        // The node key first: the detector's conferral is from a root this
        // node accepts.
        let node = sub::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        let (a, c, det) = bodies::i961_detection(&b, &t).await;
        let a_statement = bodies::statement_of(&b, &a.1).await;
        sub::state_producer_withdraws(&b, &det, &format!("{t}-agent-h"), None).await;
        let summary = b
            .delete_traces_for_agent_id_hash(&format!("{t}-agent-h"))
            .await
            .unwrap();
        assert_eq!(
            summary.detection_events_tombstoned, 1,
            "I961 sqlite: the row is erased"
        );
        bodies::i961_after_erasure(&b, &det, &a, &a_statement, &c).await;
        // RED: one column of one live projection row moved.
        b.test_execute(
            "UPDATE cirislens_derived_detection_events SET severity = 'critical' WHERE erased_at IS NULL",
        )
        .await;
        assert!(
            check_projection_rebuild(&b, SiloProjection::DetectionEvents)
                .await
                .is_err(),
            "I961 sqlite: a moved column is red"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i962_sqlite() {
        let b = sqlite().await;
        let t = tag("i962s");
        bodies::i962_refused_without_a_node_key(&b, &t).await;
        let node = format!("{t}-node");
        bodies::register_node(&b, &node).await;
        // v62.0.0 (K1) — the node key is held under its edition-2 id.
        let node = crate::federation::hard_case::test_support::node_key_id_of(&node);
        b.set_node_key_id(&node);
        bodies::i962_succeeds_with_the_node_key(&b, &node, &t).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i964_sqlite() {
        let b = sqlite().await;
        let t = tag("i964s");
        let node = sub::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        bodies::i964_the_dsar_erasure(&b, &t).await;
        // RED: both erased detections are gone, so state a live one and
        // move one column of its projection row.
        bodies::stated(
            &b,
            &crate::federation::subject_erasure_invariants::bodies::detector_seed(&t),
            &format!("{t}-agent-r"),
            &format!("{t}-trace-r"),
        )
        .await;
        b.test_execute(
            "UPDATE cirislens_derived_detection_events SET severity = 'critical' WHERE erased_at IS NULL",
        )
        .await;
        assert!(
            check_projection_rebuild(&b, SiloProjection::DetectionEvents)
                .await
                .is_err(),
            "I964 sqlite: a moved column is red"
        );
    }

    #[cfg(feature = "postgres")]
    async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("silo_projection postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return None;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i960_postgres() {
        let Some(b) = postgres().await else { return };
        let t = tag("i960p");
        let node = format!("{t}-node");
        bodies::register_node(&b, &node).await;
        // v62.0.0 (K1) — the node key is held under its edition-2 id.
        let node = crate::federation::hard_case::test_support::node_key_id_of(&node);
        b.set_node_key_id(&node);
        bodies::i960_hard_case(&b, &node, &t).await;
        b.test_execute(
            "UPDATE cirislens.hard_case_events SET detail = '{}'::jsonb \
             WHERE kind = 'consent_sla_breach'",
        )
        .await;
        assert!(
            check_projection_rebuild(&b, SiloProjection::HardCaseEvents)
                .await
                .is_err(),
            "I960 postgres: a moved column is red"
        );
        eprintln!("i960_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i961_postgres() {
        let Some(b) = postgres().await else { return };
        let t = tag("i961p");
        // The node key first: the detector's conferral is from a root this
        // node accepts.
        let node = sub::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        let (a, c, det) = bodies::i961_detection(&b, &t).await;
        let a_statement = bodies::statement_of(&b, &a.1).await;
        sub::state_producer_withdraws(&b, &det, &format!("{t}-agent-h"), None).await;
        let summary = b
            .delete_traces_for_agent_id_hash(&format!("{t}-agent-h"))
            .await
            .unwrap();
        assert_eq!(
            summary.detection_events_tombstoned, 1,
            "I961 postgres: the row is erased"
        );
        bodies::i961_after_erasure(&b, &det, &a, &a_statement, &c).await;
        // RED: one column of one live projection row moved.
        b.test_execute(
            "UPDATE cirislens_derived.detection_events SET severity = 'critical' WHERE erased_at IS NULL",
        )
        .await;
        assert!(
            check_projection_rebuild(&b, SiloProjection::DetectionEvents)
                .await
                .is_err(),
            "I961 postgres: a moved column is red"
        );
        eprintln!("i961_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i962_postgres() {
        let Some(b) = postgres().await else { return };
        let t = tag("i962p");
        bodies::i962_refused_without_a_node_key(&b, &t).await;
        let node = format!("{t}-node");
        bodies::register_node(&b, &node).await;
        // v62.0.0 (K1) — the node key is held under its edition-2 id.
        let node = crate::federation::hard_case::test_support::node_key_id_of(&node);
        b.set_node_key_id(&node);
        bodies::i962_succeeds_with_the_node_key(&b, &node, &t).await;
        eprintln!("i962_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i964_postgres() {
        let Some(b) = postgres().await else { return };
        let t = tag("i964p");
        let node = sub::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        bodies::i964_the_dsar_erasure(&b, &t).await;
        // RED: both erased detections are gone, so state a live one and
        // move one column of its projection row.
        bodies::stated(
            &b,
            &crate::federation::subject_erasure_invariants::bodies::detector_seed(&t),
            &format!("{t}-agent-r"),
            &format!("{t}-trace-r"),
        )
        .await;
        b.test_execute(
            "UPDATE cirislens_derived.detection_events SET severity = 'critical' WHERE erased_at IS NULL",
        )
        .await;
        assert!(
            check_projection_rebuild(&b, SiloProjection::DetectionEvents)
                .await
                .is_err(),
            "I964 postgres: a moved column is red"
        );
        eprintln!("i964_postgres: RAN");
    }
}
