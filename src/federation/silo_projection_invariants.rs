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
//!   The row is unpurgeable (the accountability-record family) and does not
//!   enter the federation tier (held replication).
//! - **I961 (`detection_events`)** — `put_detection_event` (twice, plus an
//!   idempotent re-put and a conflicting one), then the Art. 17 erasure of
//!   one detection's trace: the redacted row's projection is the V080
//!   tombstone, and the rebuild is byte-equal again.
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
            assert_eq!(row.tier, "local", "I960: replication is held");
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
            // Held: it does not cross to the federation tier.
            assert_eq!(
                hard_case::check_hard_case_replication_held(&row)
                    .unwrap_err()
                    .kind(),
                "federation_hard_case_replication_held"
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
        B: AttestationStore + crate::derived::DerivedSchema,
    {
        let detector = format!("{tag}-lens");
        ts::register_hybrid_key_as(b, &detector, &detector, identity_type::LENSCORE_DETECTOR).await;
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
        check_projection_rebuild(b, SiloProjection::DetectionEvents)
            .await
            .expect("I961: detection_events is its rows' rebuild");
        (a, c)
    }

    /// I961, after the runner erased `erased`'s trace: the tombstone is the
    /// redacted row's projection, the other detection is untouched, and the
    /// rebuild is byte-equal.
    pub(crate) async fn i961_after_erasure<B>(
        b: &B,
        erased: &crate::derived::DetectionEvent,
        kept: &crate::derived::DetectionEvent,
    ) where
        B: AttestationStore + crate::derived::DerivedSchema,
    {
        let row = b
            .get_attestation(&crate::derived::detection_row::detection_attestation_id(
                &erased.detection_id,
            ))
            .await
            .expect("I961: get")
            .expect("I961: the redacted row stands");
        let body = crate::derived::detection_row::project_detection_row(&row)
            .expect("I961: the redacted row projects");
        assert!(body.erased_at.is_some(), "I961: tombstoned");
        assert_eq!(body.trace_id, None, "I961: the linkage left the ROW");
        assert_eq!(body.canonical_bytes, None);
        assert!(
            b.get_detection_events(crate::derived::EventFilter {
                trace_id: Some(erased.trace_id.clone()),
                ..Default::default()
            })
            .await
            .expect("I961: read")
            .is_empty(),
            "I961: a tombstone is not returned"
        );
        assert_eq!(
            b.get_detection_events(crate::derived::EventFilter {
                trace_id: Some(kept.trace_id.clone()),
                ..Default::default()
            })
            .await
            .expect("I961: read"),
            vec![kept.clone()]
        );
        check_projection_rebuild(b, SiloProjection::DetectionEvents)
            .await
            .expect("I961: the tombstoned table is its rows' rebuild");
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
        let node = format!("{t}-node");
        bodies::register_node(&b, &node).await;
        b.set_node_key_id(&node);
        b.insert_trace_events_batch(&[bodies::trace_row(&a.trace_id, &format!("{t}-agent-h"))])
            .await
            .unwrap();
        let summary = b
            .delete_traces_for_agent_id_hash(&format!("{t}-agent-h"))
            .await
            .unwrap();
        assert_eq!(summary.detection_events_tombstoned, 1, "I961 memory");
        bodies::i961_after_erasure(&b, &a, &c).await;
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
        let node = format!("{t}-node");
        bodies::register_node(&b, &node).await;
        b.set_node_key_id(&node);
        b.insert_trace_events_batch(&[bodies::trace_row(&a.trace_id, &format!("{t}-agent-h"))])
            .await
            .unwrap();
        let summary = b
            .delete_traces_for_agent_id_hash(&format!("{t}-agent-h"))
            .await
            .unwrap();
        assert_eq!(summary.detection_events_tombstoned, 1, "I961 sqlite");
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
        let node = format!("{t}-node");
        bodies::register_node(&b, &node).await;
        b.set_node_key_id(&node);
        b.insert_trace_events_batch(&[bodies::trace_row(&a.trace_id, &format!("{t}-agent-h"))])
            .await
            .unwrap();
        let summary = b
            .delete_traces_for_agent_id_hash(&format!("{t}-agent-h"))
            .await
            .unwrap();
        assert_eq!(summary.detection_events_tombstoned, 1, "I961 postgres");
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
}
