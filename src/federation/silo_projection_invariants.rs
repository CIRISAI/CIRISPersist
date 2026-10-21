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
//! - **I961 (`detection_events`)** — `put_detection_event` (twice, plus an
//!   idempotent re-put and a conflicting one), then the DSAR erasure of one
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
//! - **I963 (the legacy rehome, lead ruling 4)** — pre-v57 silo rows (no
//!   backing row) are moved onto the plane by the first emitter after the
//!   upgrade; each rehomed row's `asserted_at` is the silo row's own
//!   recorded instant (never the rehome's clock), a second rehome adds
//!   nothing, and the projection is its rebuild after it. On sqlite and
//!   postgres; memory holds no pre-v57 rows and its rehome is a declared
//!   no-op (`store::parity`), asserted here.
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

#[cfg(test)]
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

    fn detection(trace: &str, signer: &str) -> crate::derived::DetectionEvent {
        crate::derived::DetectionEvent {
            detection_id: uuid::Uuid::new_v4(),
            trace_id: trace.to_owned(),
            body_sha256: vec![7u8; 32],
            detector: "cohort_declared_inferred_mismatch".into(),
            severity: crate::derived::DetectionSeverity::Warning,
            cohort_cell: serde_json::json!({"agent_role": "x", "deployment_region": "eu"}),
            conformity_variant: crate::derived::ConformityVariant::Numeric,
            conformity_payload: serde_json::json!({"score": 0.25}),
            lens_core_version: "1.0.0".into(),
            ratchet_calibration_version: 3,
            canonical_bytes: format!("{{\"trace\":\"{trace}\"}}").into_bytes(),
            ed25519_sig: vec![1u8; 64],
            ml_dsa_65_sig: vec![2u8; 3309],
            signing_key_id: signer.to_owned(),
            // Microsecond-clean: postgres stores `ts` at microsecond precision,
            // and the read-back compares the event whole.
            ts: crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now()),
        }
    }

    /// I961 — the writers (no erasure), then the gate. Returns the two
    /// detections the runner erases one of.
    pub(crate) async fn i961_detection<B>(
        b: &B,
        tag: &str,
    ) -> (
        crate::derived::DetectionEvent,
        crate::derived::DetectionEvent,
    )
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend,
    {
        let detector = format!("{tag}-lens");
        ts::register_hybrid_key_as(b, &detector, &detector, identity_type::LENSCORE_DETECTOR).await;
        // v58.0.0 (#1094 item 2) — the traces first, so each row names its
        // subject (the agent whose trace it scored).
        b.insert_trace_events_batch(&[
            trace_row(&format!("{tag}-trace-a"), &format!("{tag}-agent-h")),
            trace_row(&format!("{tag}-trace-c"), &format!("{tag}-agent-c")),
        ])
        .await
        .unwrap();
        let a = detection(&format!("{tag}-trace-a"), &detector);
        let c = detection(&format!("{tag}-trace-c"), &detector);
        b.put_detection_event(a.clone()).await.expect("I961: a");
        b.put_detection_event(c.clone()).await.expect("I961: c");
        b.put_detection_event(a.clone())
            .await
            .expect("I961: an identical re-put is a no-op");
        let mut moved = a.clone();
        moved.canonical_bytes = b"{\"other\":1}".to_vec();
        assert!(
            matches!(
                b.put_detection_event(moved).await,
                Err(crate::derived::Error::Conflict(_))
            ),
            "I961: different bytes under a held detection_id conflict"
        );
        // A detector that is not one: the reserved family refuses it.
        let agent = format!("{tag}-agent");
        ts::register_hybrid_key_as(b, &agent, &agent, identity_type::AGENT).await;
        assert!(
            matches!(
                b.put_detection_event(detection(&format!("{tag}-trace-x"), &agent))
                    .await,
                Err(crate::derived::Error::InvalidArgument(_))
            ),
            "I961: only a lenscore_detector emits detection:*"
        );
        let row = b
            .get_attestation(&crate::derived::detection_row::detection_attestation_id(
                &a.detection_id,
            ))
            .await
            .expect("I961: get")
            .expect("I961: the detection is a row");
        assert_eq!(
            row.attesting_key_id, detector,
            "I961: attester = the detector"
        );
        // The gate first, so a writer that moved a column is caught by it
        // before the read-back below sees the same column.
        check_projection_rebuild(b, SiloProjection::DetectionEvents)
            .await
            .expect("I961: detection_events is its rows' rebuild");
        let read = b
            .get_detection_events(crate::derived::EventFilter {
                trace_id: Some(a.trace_id.clone()),
                ..Default::default()
            })
            .await
            .expect("I961: read");
        assert_eq!(
            read,
            vec![a.clone()],
            "I961: the projection reads back the event"
        );
        (a, c)
    }

    /// I961, after the runner ran the DSAR erasure of `erased`'s trace (lead
    /// ruling on S1 item 5): the erased detection's signed row was
    /// HARD-DELETED in the erasure's transaction (never rewritten), its
    /// projection row left with it, and a purge tombstone under the
    /// erasure's own `hard_case:trace_erasure:v1` row
    /// (`steward_purge::ART17_ERASURE_BASIS`) refuses its re-admission and is
    /// never served as a purge bundle. The other detection is untouched and
    /// the table is its rows' rebuild.
    pub(crate) async fn i961_after_erasure<B>(
        b: &B,
        erased: &crate::derived::DetectionEvent,
        kept: &crate::derived::DetectionEvent,
    ) where
        B: AttestationStore + crate::derived::DerivedSchema,
    {
        let erased_row =
            crate::derived::detection_row::detection_attestation_id(&erased.detection_id);
        assert!(
            b.get_attestation(&erased_row).await.unwrap().is_none(),
            "I961: the erased detection's signed row is hard-deleted, not rewritten"
        );
        assert!(
            b.get_detection_events(crate::derived::EventFilter {
                trace_id: Some(erased.trace_id.clone()),
                ..Default::default()
            })
            .await
            .expect("I961: read")
            .is_empty(),
            "I961: the erased detection is not returned"
        );
        assert_eq!(
            b.get_detection_events(crate::derived::EventFilter {
                trace_id: Some(kept.trace_id.clone()),
                ..Default::default()
            })
            .await
            .expect("I961: read"),
            vec![kept.clone()],
            "I961: the other detection is untouched"
        );
        // v58.0.0 (#1094 item 2) — the tombstone: under a header citing the
        // producer's rule-1 `withdraws` (never the erasure's own row), SERVED, and it
        // refuses the row's re-admission.
        let notice = b
            .purge_tombstoned("attestation", &erased_row)
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
        assert_eq!(cited.target_attestation_id, erased_row);
        let withdraws = b
            .get_attestation(&cited.withdraws_attestation_id)
            .await
            .unwrap()
            .expect("I961: the cited withdraws is held");
        assert_eq!(
            withdraws.attesting_key_id, erased.signing_key_id,
            "I961: the producer"
        );
        let again = b.put_detection_event(erased.clone()).await;
        assert!(
            matches!(&again, Err(crate::derived::Error::InvalidArgument(m))
                if m.starts_with(crate::federation::steward_purge::token::TOMBSTONED)),
            "I961: the tombstone refuses the row's re-admission: {again:?}"
        );
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

    /// I963 — after the runner seeded pre-v57 silo rows (`legacy_event_id`
    /// emitted at `legacy_at`, a detection `legacy_detection` at
    /// `legacy_detection_ts`), the first emitters rehome them.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i963_the_rehome<B>(
        b: &B,
        node: &str,
        tag: &str,
        legacy_event_id: &str,
        legacy_at: chrono::DateTime<chrono::Utc>,
        legacy_detection: Option<(uuid::Uuid, chrono::DateTime<chrono::Utc>, &str)>,
    ) where
        B: AttestationStore + crate::derived::DerivedSchema,
    {
        let trunc = crate::federation::admission::truncate_to_substrate_resolution;
        // The first hard_case emitter rehomes the legacy hard_case row.
        b.record_hard_case(event(
            &format!("{tag}-new"),
            hard_case::kind::CONSENT_SLA_BREACH,
            serde_json::json!({}),
        ))
        .await
        .expect("I963: the first emitter after the upgrade");
        let row = b
            .get_attestation(&hard_case::hard_case_attestation_id(legacy_event_id))
            .await
            .unwrap()
            .expect("I963: the legacy event is a row now");
        assert_eq!(row.attesting_key_id, node);
        assert_eq!(
            row.asserted_at,
            trunc(legacy_at),
            "I963: the rehomed row is asserted at the silo row's own instant, never the boot clock"
        );
        check_projection_rebuild(b, SiloProjection::HardCaseEvents)
            .await
            .expect("I963: after the rehome, hard_case_events is its rows' rebuild");
        if let Some((detection_id, ts, detector)) = legacy_detection {
            // The first detection put rehomes the legacy detection row.
            let mut fresh = detection(&format!("{tag}-trace-new"), detector);
            fresh.ts = trunc(chrono::Utc::now());
            b.put_detection_event(fresh)
                .await
                .expect("I963: a detection put");
            let row = b
                .get_attestation(&crate::derived::detection_row::detection_attestation_id(
                    &detection_id,
                ))
                .await
                .unwrap()
                .expect("I963: the legacy detection is a row now");
            assert_eq!(row.attesting_key_id, detector);
            assert_eq!(
                row.asserted_at,
                trunc(ts),
                "I963: asserted at the detection's ts"
            );
            check_projection_rebuild(b, SiloProjection::DetectionEvents)
                .await
                .expect("I963: after the rehome, detection_events is its rows' rebuild");
        }
        // Idempotent: a second rehome (a second boot) adds nothing.
        let attester = crate::federation::attestation_admit::HardCaseAttester {
            key_id: node.to_owned(),
            identity_type: identity_type::NODE.to_owned(),
        };
        let before = b
            .list_hard_case_events(hard_case::HardCaseFilter::default())
            .await
            .unwrap();
        b.rehome_legacy_hard_case_events(&attester, chrono::Utc::now())
            .await
            .unwrap();
        b.rehome_legacy_detection_events(chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(
            b.list_hard_case_events(hard_case::HardCaseFilter::default())
                .await
                .unwrap(),
            before,
            "I963: a second rehome adds nothing"
        );
        check_projection_rebuild(b, SiloProjection::HardCaseEvents)
            .await
            .expect("I963: still its rows' rebuild");
        check_projection_rebuild(b, SiloProjection::DetectionEvents)
            .await
            .expect("I963: still its rows' rebuild");
    }

    /// I964 — the DSAR erasure of a trace with a row-backed detection (and,
    /// when the runner seeded `legacy`, a pre-v57 detection of the same
    /// trace): `expected` is the counter the erasure must report. Then the
    /// key-scoped door (`delete_traces_for_agent`) on a second trace.
    pub(crate) async fn i964_the_dsar_erasure<B>(
        b: &B,
        tag: &str,
        legacy: Option<uuid::Uuid>,
        expected: u64,
    ) where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend + Sync,
    {
        use crate::derived::detection_row as dr;
        let lens = format!("{tag}-lens");
        crate::federation::hard_case::test_support_hold(b, &lens).await;
        let agent = format!("{tag}-agent-h");
        let trace = format!("{tag}-trace");
        b.insert_trace_events_batch(&[trace_row(&trace, &agent)])
            .await
            .unwrap();
        let original = detection(&trace, &lens);
        b.put_detection_event(original.clone()).await.unwrap();
        let row_id = dr::detection_attestation_id(&original.detection_id);

        let summary = b.delete_traces_for_agent_id_hash(&agent).await.unwrap();
        assert_eq!(
            summary.detection_events_tombstoned, expected,
            "I964: the counter"
        );
        assert!(
            b.get_attestation(&row_id).await.unwrap().is_none(),
            "I964: the signed row is hard-deleted"
        );
        let gone: Vec<uuid::Uuid> = std::iter::once(original.detection_id)
            .chain(legacy)
            .collect();
        i964_no_projection_row(b, &gone).await;
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
        let again = b.put_detection_event(original.clone()).await;
        assert!(
            matches!(&again, Err(crate::derived::Error::InvalidArgument(m))
                if m.starts_with(crate::federation::steward_purge::token::TOMBSTONED)),
            "I964: a re-put is refused TOMBSTONED: {again:?}"
        );
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
        b.insert_trace_events_batch(&[trace_row(&trace2, &agent2)])
            .await
            .unwrap();
        let second = detection(&trace2, &lens);
        b.put_detection_event(second.clone()).await.unwrap();
        let row2 = dr::detection_attestation_id(&second.detection_id);
        b.delete_traces_for_agent(&agent2, &format!("{agent2}-signer"), false)
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

#[cfg(test)]
mod run {
    use super::bodies;
    use crate::federation::silo_projection::{check_projection_rebuild, SiloProjection};
    use crate::federation::subject_erasure_invariants::bodies as sub;
    use crate::store::Backend as _;

    fn tag(n: &str) -> String {
        format!("{n}-{}", uuid::Uuid::new_v4().simple())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i960_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        let t = tag("i960m");
        let node = format!("{t}-node");
        bodies::register_node(&b, &node).await;
        b.set_node_key_id(&node);
        bodies::i960_hard_case(&b, &node, &t).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i961_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        let t = tag("i961m");
        let (a, c) = bodies::i961_detection(&b, &t).await;
        let node = sub::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        let summary = b
            .delete_traces_for_agent_id_hash(&format!("{t}-agent-h"))
            .await
            .unwrap();
        assert_eq!(
            summary.detection_events_tombstoned, 1,
            "I961 memory: the row is erased"
        );
        bodies::i961_after_erasure(&b, &a, &c).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i962_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        let t = tag("i962m");
        bodies::i962_refused_without_a_node_key(&b, &t).await;
        let node = format!("{t}-node");
        bodies::register_node(&b, &node).await;
        b.set_node_key_id(&node);
        bodies::i962_succeeds_with_the_node_key(&b, &node, &t).await;
    }

    /// Memory holds no pre-v57 rows: its rehome is a no-op (a declared
    /// divergence in `store::parity`), and the gates hold.
    #[tokio::test(flavor = "multi_thread")]
    async fn i963_memory() {
        use crate::federation::FederationDirectory as _;
        let b = crate::store::memory::MemoryBackend::new();
        let t = tag("i963m");
        let node = format!("{t}-node");
        bodies::register_node(&b, &node).await;
        b.set_node_key_id(&node);
        bodies::i960_hard_case(&b, &node, &t).await;
        let before = b
            .list_hard_case_events(crate::federation::hard_case::HardCaseFilter::default())
            .await
            .unwrap();
        let attester = crate::federation::attestation_admit::HardCaseAttester {
            key_id: node.clone(),
            identity_type: crate::federation::types::identity_type::NODE.to_owned(),
        };
        use crate::federation::attestation_admit::AttestationStore as _;
        b.rehome_legacy_hard_case_events(&attester, chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(
            b.list_hard_case_events(crate::federation::hard_case::HardCaseFilter::default())
                .await
                .unwrap(),
            before
        );
        check_projection_rebuild(&b, SiloProjection::HardCaseEvents)
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i964_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        let t = tag("i964m");
        let node = sub::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        bodies::i964_the_dsar_erasure(&b, &t, None, 1).await;
    }

    /// Memory has no SQL to tamper with; its red is the rebuild of a map
    /// entry that names no row.
    #[tokio::test(flavor = "multi_thread")]
    async fn i960_memory_red_on_an_orphan_projection_row() {
        let b = crate::store::memory::MemoryBackend::new();
        let t = tag("i960mr");
        let node = format!("{t}-node");
        bodies::register_node(&b, &node).await;
        b.set_node_key_id(&node);
        bodies::i960_hard_case(&b, &node, &t).await;
        b.test_insert_orphan_hard_case_projection(&format!("{t}-orphan"));
        assert!(
            check_projection_rebuild(&b, SiloProjection::HardCaseEvents)
                .await
                .is_err(),
            "I960 memory: an entry no row produces is red"
        );
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

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i961_sqlite() {
        let b = sqlite().await;
        let t = tag("i961s");
        let (a, c) = bodies::i961_detection(&b, &t).await;
        let node = sub::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        let summary = b
            .delete_traces_for_agent_id_hash(&format!("{t}-agent-h"))
            .await
            .unwrap();
        assert_eq!(
            summary.detection_events_tombstoned, 1,
            "I961 sqlite: the row is erased"
        );
        bodies::i961_after_erasure(&b, &a, &c).await;
        // RED: a projection row whose row is gone is not a rebuild.
        b.test_execute(
            "UPDATE cirislens_derived_detection_events SET severity = 'critical' \
             WHERE erased_at IS NULL",
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
        b.set_node_key_id(&node);
        bodies::i962_succeeds_with_the_node_key(&b, &node, &t).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i963_sqlite() {
        let b = sqlite().await;
        let t = tag("i963s");
        let legacy_at: chrono::DateTime<chrono::Utc> =
            "2026-01-02T03:04:05.123456789Z".parse().unwrap();
        let detection_id = uuid::Uuid::new_v4();
        let ts: chrono::DateTime<chrono::Utc> = "2026-02-03T04:05:06.654321Z".parse().unwrap();
        let lens = format!("{t}-lens");
        crate::federation::tier_ingest::test_support::register_hybrid_key_as(
            &b,
            &lens,
            &lens,
            crate::federation::types::identity_type::LENSCORE_DETECTOR,
        )
        .await;
        // Pre-v57 silo rows, as a v56 node wrote them (no backing row).
        b.test_execute(&format!(
            "INSERT INTO hard_case_events \
                (event_id, kind, target_key_id, subject_key_id, detail, emitted_at) \
             VALUES ('{t}-legacy', 'consent_sla_breach', 'tgt', NULL, '{{\"sla_days\":3}}', \
                     '{}'); \
             INSERT INTO cirislens_derived_detection_events \
                (detection_id, trace_id, body_sha256, detector, severity, cohort_cell, \
                 conformity_variant, conformity_payload, lens_core_version, \
                 ratchet_calibration_version, canonical_bytes, ed25519_sig, ml_dsa_65_sig, \
                 signing_key_id, ts) \
             VALUES ('{detection_id}', '{t}-trace-old', zeroblob(32), \
                     'manifold_conformity_outlier', 'info', '{{}}', 'numeric', '{{}}', '1', 1, \
                     x'7b7d', zeroblob(64), zeroblob(3309), '{lens}', '{}')",
            legacy_at.to_rfc3339(),
            ts.to_rfc3339(),
        ))
        .await;
        let node = format!("{t}-node");
        bodies::register_node(&b, &node).await;
        b.set_node_key_id(&node);
        bodies::i963_the_rehome(
            &b,
            &node,
            &t,
            &format!("{t}-legacy"),
            legacy_at,
            Some((detection_id, ts, &lens)),
        )
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i964_sqlite() {
        let b = sqlite().await;
        let t = tag("i964s");
        let node = sub::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        let lens = format!("{t}-lens");
        crate::federation::hard_case::test_support_hold(&b, &lens).await;
        // A pre-v57 detection of the same trace, as a v56 node wrote it.
        let legacy = uuid::Uuid::new_v4();
        b.test_execute(&format!(
            "INSERT INTO cirislens_derived_detection_events \
                (detection_id, trace_id, body_sha256, detector, severity, cohort_cell, \
                 conformity_variant, conformity_payload, lens_core_version, \
                 ratchet_calibration_version, canonical_bytes, ed25519_sig, ml_dsa_65_sig, \
                 signing_key_id, ts) \
             VALUES ('{legacy}', '{t}-trace', zeroblob(32), 'manifold_conformity_outlier', 'info', \
                     '{{}}', 'numeric', '{{}}', '1', 1, x'7b7d', zeroblob(64), \
                     zeroblob(3309), '{lens}', '2026-02-03T04:05:06.654321+00:00')"
        ))
        .await;
        bodies::i964_the_dsar_erasure(&b, &t, Some(legacy), 2).await;
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
        let (a, c) = bodies::i961_detection(&b, &t).await;
        let node = sub::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        let summary = b
            .delete_traces_for_agent_id_hash(&format!("{t}-agent-h"))
            .await
            .unwrap();
        assert_eq!(
            summary.detection_events_tombstoned, 1,
            "I961 postgres: the row is erased"
        );
        bodies::i961_after_erasure(&b, &a, &c).await;
        b.test_execute(
            "UPDATE cirislens_derived.detection_events SET severity = 'critical' \
             WHERE erased_at IS NULL",
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
        b.set_node_key_id(&node);
        bodies::i962_succeeds_with_the_node_key(&b, &node, &t).await;
        eprintln!("i962_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i963_postgres() {
        let Some(b) = postgres().await else { return };
        let t = tag("i963p");
        let legacy_at: chrono::DateTime<chrono::Utc> =
            "2026-01-02T03:04:05.123456Z".parse().unwrap();
        let detection_id = uuid::Uuid::new_v4();
        let ts: chrono::DateTime<chrono::Utc> = "2026-02-03T04:05:06.654321Z".parse().unwrap();
        let lens = format!("{t}-lens");
        crate::federation::tier_ingest::test_support::register_hybrid_key_as(
            &b,
            &lens,
            &lens,
            crate::federation::types::identity_type::LENSCORE_DETECTOR,
        )
        .await;
        b.test_execute(&format!(
            "INSERT INTO cirislens.hard_case_events \
                (event_id, kind, target_key_id, subject_key_id, detail, emitted_at) \
             VALUES ('{t}-legacy', 'consent_sla_breach', 'tgt', NULL, \
                     '{{\"sla_days\":3}}'::jsonb, '{}'); \
             INSERT INTO cirislens_derived.detection_events \
                (detection_id, trace_id, body_sha256, detector, severity, cohort_cell, \
                 conformity_variant, conformity_payload, lens_core_version, \
                 ratchet_calibration_version, canonical_bytes, ed25519_sig, ml_dsa_65_sig, \
                 signing_key_id, ts) \
             VALUES ('{detection_id}', '{t}-trace-old', decode(repeat('00', 32), 'hex'), \
                     'manifold_conformity_outlier', 'info', '{{}}'::jsonb, 'numeric', \
                     '{{}}'::jsonb, '1', 1, decode('7b7d', 'hex'), \
                     decode(repeat('00', 64), 'hex'), decode(repeat('00', 3309), 'hex'), \
                     '{lens}', '{}')",
            legacy_at.to_rfc3339(),
            ts.to_rfc3339(),
        ))
        .await;
        let node = format!("{t}-node");
        bodies::register_node(&b, &node).await;
        b.set_node_key_id(&node);
        bodies::i963_the_rehome(
            &b,
            &node,
            &t,
            &format!("{t}-legacy"),
            legacy_at,
            Some((detection_id, ts, &lens)),
        )
        .await;
        eprintln!("i963_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i964_postgres() {
        let Some(b) = postgres().await else { return };
        let t = tag("i964p");
        let node = sub::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        let lens = format!("{t}-lens");
        crate::federation::hard_case::test_support_hold(&b, &lens).await;
        let legacy = uuid::Uuid::new_v4();
        b.test_execute(&format!(
            "INSERT INTO cirislens_derived.detection_events \
                (detection_id, trace_id, body_sha256, detector, severity, cohort_cell, \
                 conformity_variant, conformity_payload, lens_core_version, \
                 ratchet_calibration_version, canonical_bytes, ed25519_sig, ml_dsa_65_sig, \
                 signing_key_id, ts) \
             VALUES ('{legacy}', '{t}-trace', decode(repeat('00', 32), 'hex'), \
                     'manifold_conformity_outlier', 'info', '{{}}'::jsonb, 'numeric', \
                     '{{}}'::jsonb, '1', 1, decode('7b7d', 'hex'), \
                     decode(repeat('00', 64), 'hex'), decode(repeat('00', 3309), 'hex'), \
                     '{lens}', '2026-02-03T04:05:06.654321+00:00')"
        ))
        .await;
        bodies::i964_the_dsar_erasure(&b, &t, Some(legacy), 2).await;
        eprintln!("i964_postgres: RAN");
    }
}
