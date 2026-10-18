//! v58.0.0 (CIRISPersist#1094 items 2 and 3; CC 4.5.3, CC 4.5.5;
//! CLM-erasure-subject-route, CLM-reconsideration-subject-standing) —
//! **I965–I974, on every backend that has the door.**
//!
//! - **I965** — a `detection:*` row names its subject: the CC 2.3.2.1
//!   canonical hash of the scored trace's agent, when the trace is held; no
//!   subject when it is not.
//! - **I966** — the DSAR erasure is the PRODUCER's `withdraws` (CC 4.5.3,
//!   controller-only): the door plans the detector's rule-1 `withdraws`
//!   (local tier, signature deferred) and hard-deletes the row under a
//!   tombstone whose header cites it (`legal_basis` = `withdraws`), is SERVED
//!   as a purge bundle, refuses re-admission, and leaves the projection its
//!   rows' rebuild; a re-run is a no-op; the one-key door erases the same way.
//! - **I967** — refused with a reason: when the host holds no live record of
//!   the producer key the row is NOT erased and the summary names it with
//!   `erasure_producer_key_not_held`; a producer withdraws already held is
//!   reused, never doubled.
//! - **I968** — the CC 2.4.1.1 carve-out stays load-bearing: a rule-2
//!   withdraws (the scored agent bound to the canonical subject) and a rule-3
//!   withdraws (a node holding a consent_revocation proxy chain to it) of a
//!   detection row are both refused.
//! - **I969** — the erasure's hard case names nobody; V196 deletes the
//!   v57-shaped rows that did, and their `art17_erasure` headers, and the
//!   projection stays its rows' rebuild (sqlite, postgres).
//! - **I970** — an immediate-removal basis from a key holding no `takedown`
//!   duty is refused for every basis (CC 4.5.3 struck "from any claimant").
//! - **I971** — two nodes: the erasure's tombstone delivered through the
//!   planes; the receiver re-derives the producer's withdraws on its own state
//!   (after the crossing) and destroys its replica; a bundle whose withdraws has not replicated is
//!   refused retryable; one naming another record is refused.
//! - **I972** — `reconsideration:{grounds}`: the subject of the HELD target
//!   files; a filer naming itself subject of a target it is not the subject
//!   of is refused; a ruling stays with the review-holders; the action's
//!   community is the target's.
//! - **I973** — a target naming its subject by key digest admits the filer
//!   whose key digests to it, and nobody else.
//! - **I974** — the Engine door end to end (sqlite, postgres): the producer
//!   route through the Engine the Python surface calls.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::attestation_admit::AttestationStore;
    use crate::federation::silo_projection::{check_projection_rebuild, SiloProjection};
    use crate::federation::subject_erasure::{self as se, ErasureNotice};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type, Attestation};
    use crate::federation::{EmitAttestationInput, Error, FederationDirectory};

    /// A node whose key this test can sign with: `id` is the signer's
    /// derived key id, `alias` the seed source.
    pub(crate) struct Node {
        pub(crate) id: String,
        pub(crate) alias: String,
    }

    /// Register a signing node key (role `node`).
    pub(crate) async fn signing_node<B>(b: &B, tag: &str) -> Node
    where
        B: FederationDirectory + ?Sized,
    {
        let alias = format!("node-key-{tag}-0123456789abcdef")
            .replace('_', "-")
            .to_lowercase();
        let id = ts::local_signer(&alias).derived_key_id();
        ts::register_hybrid_key_as(b, &id, &alias, identity_type::NODE).await;
        Node { id, alias }
    }

    /// Emit `input` signed by `alias`'s key through the ordinary door.
    pub(crate) async fn emit_as<B>(
        b: &B,
        alias: &str,
        input: EmitAttestationInput,
    ) -> Result<String, Error>
    where
        B: FederationDirectory + Sync + ?Sized,
    {
        crate::federation::attestation_emit::emit_with_local_signer(
            b,
            &ts::local_signer(alias),
            input,
        )
        .await
        .map(|e| e.attestation_id)
    }

    pub(crate) fn detection(trace: &str, signer: &str) -> crate::derived::DetectionEvent {
        crate::derived::DetectionEvent {
            detection_id: uuid::Uuid::new_v4(),
            trace_id: trace.to_owned(),
            body_sha256: vec![7u8; 32],
            detector: "cohort_declared_inferred_mismatch".into(),
            severity: crate::derived::DetectionSeverity::Warning,
            cohort_cell: serde_json::json!({"agent_role": "x"}),
            conformity_variant: crate::derived::ConformityVariant::Numeric,
            conformity_payload: serde_json::json!({"score": 0.25}),
            lens_core_version: "1.0.0".into(),
            ratchet_calibration_version: 3,
            canonical_bytes: format!("{{\"trace\":\"{trace}\"}}").into_bytes(),
            ed25519_sig: vec![1u8; 64],
            ml_dsa_65_sig: vec![2u8; 3309],
            signing_key_id: signer.to_owned(),
            ts: crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now()),
        }
    }

    /// A detector key, a held trace of `agent`, and its detection: the row id.
    pub(crate) async fn detected<B>(b: &B, tag: &str, agent: &str, trace: &str) -> String
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend,
    {
        let lens = format!("{tag}-lens");
        crate::federation::hard_case::test_support_hold(b, &lens).await;
        b.insert_trace_events_batch(&[
            crate::federation::silo_projection_invariants::bodies::trace_row(trace, agent),
        ])
        .await
        .unwrap();
        let d = detection(trace, &lens);
        b.put_detection_event(d.clone()).await.unwrap();
        crate::derived::detection_row::detection_attestation_id(&d.detection_id)
    }

    /// The trace_erasure hard case rows, as recorded.
    async fn erasure_events<B: FederationDirectory>(
        b: &B,
    ) -> Vec<crate::federation::HardCaseEvent> {
        b.list_hard_case_events(crate::federation::hard_case::HardCaseFilter {
            kind: Some(crate::federation::hard_case::kind::TRACE_ERASURE.to_owned()),
            since: None,
        })
        .await
        .unwrap()
    }

    /// The hard case names nobody: no member, anywhere in the row, carries
    /// the agent or its signing key.
    fn assert_subject_free(e: &crate::federation::HardCaseEvent, agent: &str, what: &str) {
        assert_eq!(e.target_key_id, None, "{what}: no target");
        assert_eq!(e.subject_key_id, None, "{what}: no subject");
        assert!(
            !crate::federation::hard_case::trace_erasure_names_its_subject(e),
            "{what}: {e:?}"
        );
        let json = serde_json::to_string(e).unwrap();
        assert!(
            !json.contains(agent),
            "{what}: the row names the agent: {json}"
        );
        let subject = se::agent_subject(agent).unwrap();
        assert!(
            !json.contains(&subject),
            "{what}: the row names the subject: {json}"
        );
    }

    // ── I965 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i965_a_detection_names_its_subject<B>(b: &B, tag: &str)
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend,
    {
        let agent = format!("{tag}-agent");
        let held = detected(b, tag, &agent, &format!("{tag}-trace")).await;
        let row = b.get_attestation(&held).await.unwrap().unwrap();
        assert_eq!(
            row.subject_key_ids,
            vec![se::agent_subject(&agent).unwrap()],
            "I965: the row names the scored agent's canonical subject"
        );
        // A detection of a trace this node does not hold names no subject.
        let lens = format!("{tag}-lens");
        let d = detection(&format!("{tag}-trace-unheld"), &lens);
        b.put_detection_event(d.clone()).await.unwrap();
        let row = b
            .get_attestation(&crate::derived::detection_row::detection_attestation_id(
                &d.detection_id,
            ))
            .await
            .unwrap()
            .unwrap();
        assert!(
            row.subject_key_ids.is_empty(),
            "I965: never a guessed subject"
        );
        check_projection_rebuild(b, SiloProjection::DetectionEvents)
            .await
            .expect("I965: the projection is its rows' rebuild");
    }

    // ── I966 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i966_the_erasure_is_the_producers_withdraws<B>(b: &B, tag: &str)
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend + Sync,
    {
        let agent = format!("{tag}-agent");
        let subject = se::agent_subject(&agent).unwrap();
        let row_id = detected(b, tag, &agent, &format!("{tag}-trace")).await;
        let producer = b
            .get_attestation(&row_id)
            .await
            .unwrap()
            .unwrap()
            .attesting_key_id;

        let summary = b.delete_traces_for_agent_id_hash(&agent).await.unwrap();
        assert_eq!(summary.detection_events_tombstoned, 1, "I966: the counter");
        assert!(
            summary.detection_rows_refused.is_empty(),
            "I966: nothing refused"
        );
        assert!(
            b.get_attestation(&row_id).await.unwrap().is_none(),
            "I966: the row is hard-deleted"
        );
        let notice_id = b
            .purge_tombstoned("attestation", &row_id)
            .await
            .unwrap()
            .expect("I966: tombstoned");
        let header = b.purge_execution(&notice_id).await.unwrap().unwrap();
        assert_eq!(header.legal_basis, se::WITHDRAWS_AUTHORITY);
        assert_eq!(
            header.claimant_key_id, producer,
            "I966: the producer claims"
        );
        assert!(
            header.finalized_at.is_some(),
            "I966: finalized at execution"
        );
        let cited = ErasureNotice::parse(&serde_json::from_str(&header.notice_jcs).unwrap())
            .expect("I966: the header cites an erasure notice");
        assert_eq!(cited.target_attestation_id, row_id);
        let w = b
            .get_attestation(&cited.withdraws_attestation_id)
            .await
            .unwrap()
            .expect("I966: the producer's withdraws is held");
        assert_eq!(w.attestation_type, attestation_type::WITHDRAWS);
        assert_eq!(
            w.attesting_key_id, producer,
            "I966: signed by the producer key"
        );
        assert_eq!(w.tier, "local", "I966: signature deferred to the crossing");
        assert!(
            !header.notice_jcs.contains(&agent) && !header.notice_jcs.contains(&subject),
            "I966: the notice names no subject"
        );
        let bundles = crate::federation::steward_purge::list_purge_bundles_since(b, None, 100)
            .await
            .unwrap();
        let served = bundles
            .iter()
            .find(|x| ErasureNotice::parse(&x.notice.envelope).as_ref() == Some(&cited))
            .expect("I966: the erasure's tombstone is SERVED");
        assert_eq!(served.record_ids, vec![format!("attestation:{row_id}")]);
        let events = erasure_events(b).await;
        assert_eq!(events.len(), 1);
        assert_subject_free(&events[0], &agent, "I966");
        assert_eq!(events[0].detail["detection_rows_erased"], 1);
        check_projection_rebuild(b, SiloProjection::DetectionEvents)
            .await
            .expect("I966: the projection is its rows' rebuild");
        check_projection_rebuild(b, SiloProjection::HardCaseEvents)
            .await
            .expect("I966: hard_case_events is its rows' rebuild");
        let again = b.delete_traces_for_agent_id_hash(&agent).await.unwrap();
        assert_eq!(
            (again.trace_events, again.detection_events_tombstoned),
            (0, 0),
            "I966: a re-run is a no-op"
        );

        // The one-key door, the same route.
        let agent2 = format!("{tag}-agent-k");
        let row2 = detected(b, &format!("{tag}k"), &agent2, &format!("{tag}-trace-k")).await;
        let signer_key = format!("{agent2}-signer");
        let s2 = b
            .delete_traces_for_agent(&agent2, &signer_key, false)
            .await
            .unwrap();
        assert!(s2.detection_rows_refused.is_empty());
        assert!(b.get_attestation(&row2).await.unwrap().is_none());
        assert!(b
            .purge_tombstoned("attestation", &row2)
            .await
            .unwrap()
            .is_some());
        let events = erasure_events(b).await;
        let keyed = events
            .iter()
            .find(|e| e.detail["op"] == crate::federation::hard_case::trace_erasure_op::ONE_KEY)
            .expect("I966: the one-key door's hard case");
        assert_subject_free(keyed, &agent2, "I966 one-key");
        assert!(!serde_json::to_string(keyed).unwrap().contains(&signer_key));
    }

    // ── I967 ──────────────────────────────────────────────────────────────
    /// The seed: a detection of `agent`'s trace and, when `voluntary`, its
    /// producer's own rule-1 retraction already held. Returns `(row, producer)`.
    pub(crate) async fn i967_seed<B>(
        b: &B,
        tag: &str,
        agent: &str,
        voluntary: bool,
    ) -> (String, String)
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend + Sync,
    {
        let row_id = detected(b, tag, agent, &format!("{tag}-trace")).await;
        let target = b.get_attestation(&row_id).await.unwrap().unwrap();
        if voluntary {
            let mut w = ts::bare_attestation(
                &format!("{tag}-producer-withdraws"),
                &target.attesting_key_id,
                &target.attesting_key_id,
                &crate::federation::withdraws_attestation_envelope(
                    &row_id,
                    &target.attestation_type,
                ),
            );
            w.attestation_type = attestation_type::WITHDRAWS.into();
            w.cohort_scope = target.cohort_scope.clone();
            let w = ts::seal_row(&target.attesting_key_id, w);
            b.put_attestation(crate::federation::types::SignedAttestation { attestation: w })
                .await
                .expect("I967: the producer retracts its own row");
        }
        (row_id, target.attesting_key_id)
    }

    /// After the runner expired the producer key's record: the row is refused
    /// with a reason, left in place, counted; nothing is tombstoned.
    pub(crate) async fn i967_refused_with_reason<B>(b: &B, agent: &str, row_id: &str)
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend + Sync,
    {
        let summary = b.delete_traces_for_agent_id_hash(agent).await.unwrap();
        assert_eq!(summary.trace_events, 1, "I967: the trace corpus goes");
        assert_eq!(
            summary.detection_events_tombstoned, 0,
            "I967: the row is not erased"
        );
        assert_eq!(
            summary.detection_rows_refused,
            vec![se::ErasureRefusal {
                record_id: format!("attestation:{row_id}"),
                reason: se::token::PRODUCER_KEY_NOT_HELD.to_owned(),
            }],
            "I967: refused WITH a reason, named in the summary"
        );
        assert!(
            b.get_attestation(row_id).await.unwrap().is_some(),
            "I967: left in place"
        );
        assert!(b
            .purge_tombstoned("attestation", row_id)
            .await
            .unwrap()
            .is_none());
        let events = erasure_events(b).await;
        assert_eq!(
            events[0].detail["detection_rows_refused"], 1,
            "I967: counted"
        );
        check_projection_rebuild(b, SiloProjection::DetectionEvents)
            .await
            .expect("I967: rebuild");
    }

    /// A producer withdraws already held is the authority: reused, not doubled.
    pub(crate) async fn i967_a_held_producer_withdraws_is_reused<B>(b: &B, tag: &str)
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend + Sync,
    {
        let agent = format!("{tag}-agent-v");
        let (row_id, producer) = i967_seed(b, &format!("{tag}v"), &agent, true).await;
        b.delete_traces_for_agent_id_hash(&agent).await.unwrap();
        assert!(b.get_attestation(&row_id).await.unwrap().is_none());
        let n = b
            .purge_tombstoned("attestation", &row_id)
            .await
            .unwrap()
            .unwrap();
        let header = b.purge_execution(&n).await.unwrap().unwrap();
        let cited =
            ErasureNotice::parse(&serde_json::from_str(&header.notice_jcs).unwrap()).unwrap();
        assert_eq!(
            cited.withdraws_attestation_id,
            format!("{tag}v-producer-withdraws")
        );
        let mine = b
            .list_attestations_referencing(&row_id)
            .await
            .unwrap()
            .into_iter()
            .filter(|w| w.attesting_key_id == producer)
            .count();
        assert_eq!(mine, 1, "I967: one producer withdraws, never two");
    }

    // ── I968 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i968_the_carve_out_stays<B>(b: &B, tag: &str)
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend + Sync,
    {
        let agent = format!("{tag}-agent");
        let subject = se::agent_subject(&agent).unwrap();
        let row_id = detected(b, tag, &agent, &format!("{tag}-trace")).await;
        let target = b.get_attestation(&row_id).await.unwrap().unwrap();
        let withdraws_of = |t: &Attestation| {
            EmitAttestationInput::with_envelope(
                attestation_type::WITHDRAWS,
                crate::federation::envelope::EnvelopeCore::from_value(
                    crate::federation::withdraws_attestation_envelope(
                        &t.attestation_id,
                        &t.attestation_type,
                    ),
                )
                .unwrap(),
                t.cohort_scope.clone(),
            )
        };
        // Rule 2: the scored agent's key bound to the canonical subject.
        let agent_key = signing_node_as(b, &format!("{tag}ag"), identity_type::AGENT).await;
        let hex = subject.strip_prefix("canonical:sha256:").unwrap();
        let bind = EmitAttestationInput::with_envelope(
            attestation_type::SCORES,
            crate::federation::envelope::EnvelopeCore::from_value(serde_json::json!({
                "dimension": format!("identity:canonical_binding:{hex}"),
                "score": 1.0, "confidence": 1.0,
            }))
            .unwrap(),
            "federation",
        );
        emit_as(b, &agent_key.alias, bind)
            .await
            .expect("I968: the agent binds the canonical subject");
        let e = emit_as(b, &agent_key.alias, withdraws_of(&target))
            .await
            .expect_err("I968: rule 2 does not reach a detection row");
        assert_eq!(
            e.kind(),
            "federation_withdraws_not_admitted",
            "I968 rule 2: {e}"
        );
        // Rule 3: a node holding a consent_revocation proxy chain to the
        // subject (the subject registered so the edge can name it).
        ts::register_hybrid_key_as(b, &subject, &subject, identity_type::AGENT).await;
        let node = signing_node(b, &format!("{tag}n")).await;
        let mut gi = EmitAttestationInput::with_envelope(
            attestation_type::DELEGATES_TO,
            crate::federation::envelope::EnvelopeCore::from_value(
                crate::federation::delegates_to_envelope(
                    &subject,
                    &["consent_revocation".to_owned()],
                    false,
                ),
            )
            .unwrap(),
            "self",
        );
        gi.attested_key_id = Some(subject.clone());
        emit_as(b, &node.alias, gi)
            .await
            .expect("I968: the proxy grant itself is admissible");
        let e = emit_as(b, &node.alias, withdraws_of(&target))
            .await
            .expect_err("I968: rule 3 does not reach a detection row");
        assert_eq!(
            e.kind(),
            "federation_withdraws_not_admitted",
            "I968 rule 3: {e}"
        );
        assert!(b.get_attestation(&row_id).await.unwrap().is_some());
    }

    /// [`signing_node`] with another role.
    pub(crate) async fn signing_node_as<B>(b: &B, tag: &str, role: &str) -> Node
    where
        B: FederationDirectory + ?Sized,
    {
        let alias = format!("{role}-key-{tag}-0123456789abcdef")
            .replace('_', "-")
            .to_lowercase();
        let id = ts::local_signer(&alias).derived_key_id();
        ts::register_hybrid_key_as(b, &id, &alias, role).await;
        Node { id, alias }
    }

    // ── I969 ──────────────────────────────────────────────────────────────
    /// v57-shaped rows, seeded on a store migrated through V195: a
    /// `hard_case:trace_erasure:v1` row naming its agent and the
    /// `art17_erasure` header citing it (with its tombstone).
    // I969 seeds a V195-migrated store: the SQL backends only.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) fn v57_trace_erasure_event(agent: &str) -> crate::federation::HardCaseEvent {
        crate::federation::HardCaseEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            kind: crate::federation::hard_case::kind::TRACE_ERASURE.to_owned(),
            target_key_id: Some(agent.to_owned()),
            subject_key_id: None,
            detail: serde_json::json!({
                "agent_id_hash": agent, "trace_events": 1, "trace_llm_calls": 0,
                "detection_events_tombstoned": 1,
            }),
            emitted_at: chrono::Utc::now(),
        }
    }

    /// Seed, on a store migrated through V195 with `node` as its node key: a
    /// v57-shaped `hard_case:trace_erasure:v1` row naming `agent`, the
    /// `art17_erasure` header citing it (and its tombstone), and a v58
    /// subject-free erasure row beside them. Returns `(v57 event id, v57
    /// notice id, v58 event id)`.
    // I969 seeds a V195-migrated store: the SQL backends only.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i969_seed<B>(b: &B, node: &str, agent: &str) -> (String, String, String)
    where
        B: AttestationStore,
    {
        use crate::federation::attestation_admit::{
            plan_hard_case_row, HardCaseAttester, PlanInstants,
        };
        use crate::federation::steward_purge::{
            self as sp, PurgeExecution, PurgePlane, PurgeTombstone,
        };
        use sha2::Digest as _;
        let now =
            crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
        let attester = HardCaseAttester {
            key_id: node.to_owned(),
            identity_type: identity_type::NODE.to_owned(),
        };
        let v57 = v57_trace_erasure_event(agent);
        let planned = plan_hard_case_row(
            &v57,
            &attester,
            PlanInstants {
                fold_at: now,
                received_at: now,
            },
        )
        .unwrap();
        let row = planned.row.clone();
        b.store_planned_hard_case(planned).await.unwrap();
        let notice_jcs = String::from_utf8(
            crate::federation::attestation_emit::canonicalize(&row.attestation_envelope).unwrap(),
        )
        .unwrap();
        let notice_id = hex::encode(sha2::Sha256::digest(notice_jcs.as_bytes()));
        let gone = format!("gone-{agent}");
        b.purge_put_execution(
            &PurgeExecution {
                notice_id: notice_id.clone(),
                selection_digest: sp::selection_digest(&[format!("attestation:{gone}")]),
                claimant_key_id: node.to_owned(),
                legal_basis: "art17_erasure".to_owned(),
                record_count: 1,
                notice_jcs,
                cosignatures_json: "[]".to_owned(),
                executed_by: node.to_owned(),
                origin: sp::origin::LOCAL.to_owned(),
                executed_at: now,
                admitted_at: now,
                finalized_at: Some(now),
            },
            &[PurgeTombstone {
                notice_id: notice_id.clone(),
                ordinal: 0,
                plane: PurgePlane::Attestation,
                record_ref: gone,
                derived_from: None,
            }],
        )
        .await
        .unwrap();
        let v58 = crate::federation::hard_case::trace_erasure_event(
            &crate::federation::hard_case::TraceErasureCounts {
                op: crate::federation::hard_case::trace_erasure_op::FULL,
                trace_events: 1,
                ..Default::default()
            },
            now,
        );
        b.record_hard_case(v58.clone()).await.unwrap();
        (v57.event_id, notice_id, v58.event_id)
    }

    /// After V196 ran over the seeded rows: the v57 row and its header are
    /// gone, a v58 row (seeded beside them) stays, and the projections are
    /// their rows' rebuild.
    // I969 seeds a V195-migrated store: the SQL backends only.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i969_after_v196<B>(
        b: &B,
        v57_event_id: &str,
        v57_notice: &str,
        v58_event_id: &str,
        agent: &str,
    ) where
        B: AttestationStore,
    {
        use crate::federation::hard_case::hard_case_attestation_id;
        assert!(
            b.get_attestation(&hard_case_attestation_id(v57_event_id))
                .await
                .unwrap()
                .is_none(),
            "I969: V196 deletes the v57 row that names its subject"
        );
        assert!(
            b.purge_execution(v57_notice).await.unwrap().is_none(),
            "I969: and the art17_erasure header citing it"
        );
        let events = erasure_events(b).await;
        assert!(events.iter().all(|e| e.event_id != v57_event_id));
        let kept = events
            .iter()
            .find(|e| e.event_id == v58_event_id)
            .expect("I969: a subject-free row stays");
        assert_subject_free(kept, agent, "I969");
        check_projection_rebuild(b, SiloProjection::HardCaseEvents)
            .await
            .expect("I969: hard_case_events is its rows' rebuild after V196");
    }

    // ── I970 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i970_no_basis_from_any_claimant<D>(d: &D)
    where
        D: FederationDirectory + Sync,
    {
        use crate::federation::takedown_tombstone::{self as td, token};
        let dir = d.as_dyn_directory();
        let producer = "i970-producer-0123456789abcdefghij";
        let subject = "i970-subject-0123456789abcdefghijk";
        let stranger = "i970-stranger-0123456789abcdefghij";
        ts::register_hybrid_key(dir, stranger).await;
        let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            format!("i970-{}", uuid::Uuid::new_v4()).as_bytes(),
        ));
        crate::federation::doors_takedown_invariants::bodies::establish(
            dir, producer, subject, &sha,
        )
        .await;
        for basis in td::IMMEDIATE_REMOVAL_BASES {
            let e = td::takedown_authority(dir, stranger, &sha, basis)
                .await
                .expect_err("I970: an immediate-removal basis from a non-duty-holder");
            assert_eq!(e.kind(), token::UNAUTHORISED, "I970 {basis}: {e}");
            td::takedown_authority(dir, subject, &sha, basis)
                .await
                .unwrap_or_else(|e| {
                    panic!("I970 {basis}: the content's subject holds the duty: {e}")
                });
        }
    }

    // ── I971 ──────────────────────────────────────────────────────────────
    /// `a` erases; its rows reach `b_` as a peer's would (the signed grant
    /// and withdraws by the ordinary put door, the detection by `b_`'s own
    /// detection door over the same trace), then `a`'s served bundle is
    /// applied on `b_`.
    pub(crate) async fn i971_the_tombstone_delivered<B>(a: &B, b_: &B, node_a: &Node, tag: &str)
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend + Sync,
    {
        let node_b = signing_node(b_, &format!("{tag}b")).await;
        // B knows A's node key (it verifies A's rows) under A's role.
        ts::register_hybrid_key_as(b_, &node_a.id, &node_a.alias, identity_type::NODE).await;
        let agent = format!("{tag}-agent");
        let trace = format!("{tag}-trace");
        let lens = format!("{tag}-lens");
        crate::federation::hard_case::test_support_hold(a, &lens).await;
        crate::federation::hard_case::test_support_hold(b_, &lens).await;
        let d = detection(&trace, &lens);
        for s in [a, b_] {
            s.insert_trace_events_batch(&[
                crate::federation::silo_projection_invariants::bodies::trace_row(&trace, &agent),
            ])
            .await
            .unwrap();
            s.put_detection_event(d.clone()).await.unwrap();
        }
        let row_id = crate::derived::detection_row::detection_attestation_id(&d.detection_id);
        let _ = node_a;
        a.delete_traces_for_agent_id_hash(&agent).await.unwrap();
        let bundles = crate::federation::steward_purge::list_purge_bundles_since(a, None, 100)
            .await
            .unwrap();
        let bundle = bundles
            .iter()
            .find(|x| se::is_erasure_notice_envelope(&x.notice.envelope))
            .expect("I971: A serves the erasure's tombstone")
            .clone();
        // Over JSON, as a peer receives it.
        let bundle: crate::federation::steward_purge::PurgeBundle =
            serde_json::from_str(&serde_json::to_string(&bundle).unwrap()).unwrap();

        // The withdraws has not reached B yet: retryable.
        let e = se::apply_replicated_erasure(b_, &bundle, &node_b.id)
            .await
            .expect_err("I971: the withdraws is not held on B");
        assert_eq!(e.kind(), se::token::WITHDRAWS_UNHELD, "I971: {e}");
        assert!(b_.get_attestation(&row_id).await.unwrap().is_some());
        // A bundle naming another record: refused.
        let mut forged = bundle.clone();
        forged.record_ids = vec!["attestation:someone-else".into()];
        let e = se::apply_replicated_erasure(b_, &forged, &node_b.id)
            .await
            .expect_err("I971: an erasure names exactly its target");
        assert_eq!(e.kind(), se::token::UNAUTHORISED, "I971: {e}");

        // The producer's withdraws crosses (the detector signs it, as it signs
        // its detection) and replicates to B through B's own door.
        let cited = ErasureNotice::parse(&bundle.notice.envelope).unwrap();
        let mut w = a
            .get_attestation(&cited.withdraws_attestation_id)
            .await
            .unwrap()
            .unwrap();
        w.tier = crate::federation::types::attestation_tier::FEDERATION.to_owned();
        w.withdraws_admission_rule = None;
        let w = ts::seal_row(&lens, w);
        b_.put_attestation(crate::federation::types::SignedAttestation { attestation: w })
            .await
            .unwrap_or_else(|e| panic!("I971: B admits the producer's withdraws: {e}"));
        let out = se::apply_replicated_erasure(b_, &bundle, &node_b.id)
            .await
            .expect("I971: B re-derives the withdraws on its own state");
        assert_eq!(out.tombstoned, 1);
        assert!(
            b_.get_attestation(&row_id).await.unwrap().is_none(),
            "I971: B's replica is destroyed on receipt"
        );
        let n = b_
            .purge_tombstoned("attestation", &row_id)
            .await
            .unwrap()
            .expect("I971: B holds the tombstone");
        let header = b_.purge_execution(&n).await.unwrap().unwrap();
        assert_eq!(
            header.origin,
            crate::federation::steward_purge::origin::REPLICATED
        );
        assert!(header.finalized_at.is_some(), "I971: finalized on receipt");
        let again = b_.put_detection_event(d.clone()).await;
        assert!(again.is_err(), "I971: B refuses the row's re-admission");
        check_projection_rebuild(b_, SiloProjection::DetectionEvents)
            .await
            .expect("I971: B's projection is its rows' rebuild");
        // Re-applying is idempotent.
        let again = se::apply_replicated_erasure(b_, &bundle, &node_b.id)
            .await
            .unwrap();
        assert_eq!(again.tombstoned, 0);
    }

    // ── I972 / I973 ──────────────────────────────────────────────────────
    fn scores_row(
        id: &str,
        attester: &str,
        envelope: serde_json::Value,
        subjects: &[&str],
        scope: &str,
    ) -> Attestation {
        let mut row = ts::bare_attestation(id, attester, attester, &envelope);
        row.attestation_type = attestation_type::SCORES.into();
        row.subject_key_ids = subjects.iter().map(|s| (*s).to_owned()).collect();
        row.cohort_scope = scope.to_owned();
        ts::seal_row(attester, row)
    }

    async fn put(dir: &dyn FederationDirectory, row: Attestation) -> Result<(), Error> {
        dir.put_attestation(crate::federation::types::SignedAttestation { attestation: row })
            .await
            .map(|_| ())
    }

    fn reconsideration(
        id: &str,
        filer: &str,
        target: &str,
        extra: serde_json::Value,
        subjects: &[&str],
    ) -> Attestation {
        let mut env = serde_json::json!({
            "dimension": "reconsideration:new_evidence:v1",
            "score": 1.0, "confidence": 1.0,
            "references_attestation_id": target,
        });
        for (k, v) in extra.as_object().unwrap() {
            env[k] = v.clone();
        }
        scores_row(id, filer, env, subjects, "federation")
    }

    pub(crate) async fn i972_the_subject_of_the_target_files<D>(d: &D, tag: &str)
    where
        D: FederationDirectory + Sync,
    {
        let dir = d.as_dyn_directory();
        let k = |n: &str| format!("i972-{n}-{tag}-0123456789abcdefghij");
        let (moderator, subject, stranger) = (k("mod"), k("subj"), k("stranger"));
        let comm = format!("i972-comm-{tag}");
        crate::federation::doors_takedown_invariants::bodies::community_of(dir, &comm, &moderator)
            .await;
        for key in [&subject, &stranger] {
            ts::register_hybrid_key(dir, key).await;
        }
        // The prior action: the moderator's row about `subject` in the room.
        let target = format!("i972-target-{tag}");
        put(
            dir,
            scores_row(
                &target,
                &moderator,
                serde_json::json!({
                    "dimension": "moderation:harassment:v1",
                    "score": -1.0, "confidence": 1.0, "community_id": comm,
                }),
                &[&subject],
                // The subject is no member of the room: a federation-scope
                // row naming the room carries the action (CC 4.5.5's target).
                "federation",
            ),
        )
        .await
        .expect("I972: the prior action");
        // (1) the subject of the held target files: admitted.
        put(
            dir,
            reconsideration(
                &format!("i972-r1-{tag}"),
                &subject,
                &target,
                serde_json::json!({}),
                &[],
            ),
        )
        .await
        .expect("I972: the target's subject files");
        // (2) a stranger naming ITSELF subject: refused (never self-declared).
        let e = put(
            dir,
            reconsideration(
                &format!("i972-r2-{tag}"),
                &stranger,
                &target,
                serde_json::json!({}),
                &[&stranger],
            ),
        )
        .await
        .expect_err("I972: a self-declared subject is no standing");
        assert_eq!(
            e.kind(),
            "federation_delegated_scope_unauthorized",
            "I972: {e}"
        );
        // (3) the subject RULES: refused — the ruling stays with review-holders.
        let e = put(
            dir,
            reconsideration(
                &format!("i972-r3-{tag}"),
                &subject,
                &target,
                serde_json::json!({"outcome": "reversed"}),
                &[],
            ),
        )
        .await
        .expect_err("I972: the subject cannot rule");
        assert_eq!(
            e.kind(),
            "federation_delegated_scope_unauthorized",
            "I972: {e}"
        );
        // (4) the review-holder rules: admitted.
        put(
            dir,
            reconsideration(
                &format!("i972-r4-{tag}"),
                &moderator,
                &target,
                serde_json::json!({"outcome": "upheld"}),
                &[],
            ),
        )
        .await
        .expect("I972: the review-holder rules");
        // (5) the action's community is the target's.
        let e = put(
            dir,
            reconsideration(
                &format!("i972-r5-{tag}"),
                &subject,
                &target,
                serde_json::json!({"community_id": format!("{comm}-other")}),
                &[],
            ),
        )
        .await
        .expect_err("I972: a filing naming another community");
        assert!(
            e.to_string()
                .contains(crate::federation::admission::RECONSIDERATION_COMMUNITY_MISMATCH),
            "I972: {e}"
        );
        // (6) a target not held here: the subject arm is empty.
        let e = put(
            dir,
            reconsideration(
                &format!("i972-r6-{tag}"),
                &subject,
                &format!("i972-absent-{tag}"),
                serde_json::json!({}),
                &[&subject],
            ),
        )
        .await
        .expect_err("I972: no held target, no subject standing");
        assert_eq!(
            e.kind(),
            "federation_delegated_scope_unauthorized",
            "I972: {e}"
        );
        // (7) a licence target: not this arm (CIRISPersist#1036 item 5).
        let licence = ts::bare_attestation(
            "i972-licence",
            &moderator,
            &subject,
            &serde_json::json!({"dimension": "licensure:board:v1"}),
        );
        let mut licence = licence;
        licence.subject_key_ids = vec![subject.clone()];
        assert!(
            crate::federation::admission::reconsideration_target_subjects(dir, &subject, &licence)
                .await
                .unwrap()
                .is_empty(),
            "I972: a licence's subject files under its own arm"
        );
    }

    pub(crate) async fn i973_a_digest_named_subject<D>(d: &D, tag: &str)
    where
        D: FederationDirectory + Sync,
    {
        let dir = d.as_dyn_directory();
        let k = |n: &str| format!("i973-{n}-{tag}-0123456789abcdefghij");
        let (moderator, subject, other) = (k("mod"), k("subj"), k("other"));
        let comm = format!("i973-comm-{tag}");
        crate::federation::doors_takedown_invariants::bodies::community_of(dir, &comm, &moderator)
            .await;
        for key in [&subject, &other] {
            ts::register_hybrid_key(dir, key).await;
        }
        let rec = dir.lookup_public_key(&subject).await.unwrap().unwrap();
        let digest = crate::federation::key_digest::Sha256Ed25519Raw::from_pubkey_base64(
            &rec.pubkey_ed25519_base64,
        )
        .unwrap()
        .to_hex();
        let target = format!("i973-target-{tag}");
        put(
            dir,
            scores_row(
                &target,
                &moderator,
                serde_json::json!({
                    "dimension": "moderation:harassment:v1",
                    "score": -1.0, "confidence": 1.0, "community_id": comm,
                    "subject_sha256_ed25519_raw": digest,
                }),
                &[],
                "community",
            ),
        )
        .await
        .expect("I973: the prior action names its subject by digest");
        put(
            dir,
            reconsideration(
                &format!("i973-r1-{tag}"),
                &subject,
                &target,
                serde_json::json!({}),
                &[],
            ),
        )
        .await
        .expect("I973: the filer whose key digests to the subject files");
        let e = put(
            dir,
            reconsideration(
                &format!("i973-r2-{tag}"),
                &other,
                &target,
                serde_json::json!({}),
                &[],
            ),
        )
        .await
        .expect_err("I973: any other filer is refused");
        assert_eq!(
            e.kind(),
            "federation_delegated_scope_unauthorized",
            "I973: {e}"
        );
    }
}

#[cfg(test)]
mod run {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}-{}", uuid::Uuid::new_v4().simple())
    }

    macro_rules! on_every_backend {
        ($name:ident, |$b:ident, $t:ident| $body:expr) => {
            mod $name {
                #[allow(unused_imports)]
                use super::*;

                #[tokio::test(flavor = "multi_thread")]
                async fn memory() {
                    let $b = crate::store::memory::MemoryBackend::new();
                    let $t = tag(concat!(stringify!($name), "m"));
                    $body
                }

                #[cfg(feature = "sqlite")]
                #[tokio::test(flavor = "multi_thread")]
                async fn sqlite() {
                    use crate::store::Backend as _;
                    let $b = crate::store::sqlite::SqliteBackend::open_in_memory()
                        .await
                        .unwrap();
                    $b.run_migrations().await.unwrap();
                    let $t = tag(concat!(stringify!($name), "s"));
                    $body
                }

                #[cfg(feature = "postgres")]
                #[tokio::test(flavor = "multi_thread")]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        eprintln!(concat!(
                            stringify!($name),
                            " postgres: no base DSN — SKIPPED"
                        ));
                        return;
                    };
                    let $b = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    $b.run_migrations().await.unwrap();
                    let $t = tag(concat!(stringify!($name), "p"));
                    $body;
                    eprintln!(concat!(stringify!($name), "_postgres: RAN"));
                }
            }
        };
    }

    on_every_backend!(i965, |b, t| {
        bodies::i965_a_detection_names_its_subject(&b, &t).await;
    });

    on_every_backend!(i966, |b, t| {
        let node = bodies::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        bodies::i966_the_erasure_is_the_producers_withdraws(&b, &t).await;
    });

    on_every_backend!(i967_reuse, |b, t| {
        let node = bodies::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        bodies::i967_a_held_producer_withdraws_is_reused(&b, &t).await;
    });

    on_every_backend!(i968, |b, t| {
        let node = bodies::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        bodies::i968_the_carve_out_stays(&b, &t).await;
    });

    // I967 — the producer key's record expired (a per-backend seam).
    #[tokio::test(flavor = "multi_thread")]
    async fn i967_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        let t = tag("i967m");
        let node = bodies::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        let agent = format!("{t}-agent");
        let (row, producer) = bodies::i967_seed(&b, &t, &agent, false).await;
        b.test_expire_key(&producer);
        bodies::i967_refused_with_reason(&b, &agent, &row).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i967_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let t = tag("i967s");
        let node = bodies::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        let agent = format!("{t}-agent");
        let (row, producer) = bodies::i967_seed(&b, &t, &agent, false).await;
        b.test_execute(&format!(
            "UPDATE federation_keys SET valid_until = '2020-01-01T00:00:00+00:00' \
             WHERE key_id = '{producer}'"
        ))
        .await;
        bodies::i967_refused_with_reason(&b, &agent, &row).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i967_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("i967 postgres: no base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let t = tag("i967p");
        let node = bodies::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        let agent = format!("{t}-agent");
        let (row, producer) = bodies::i967_seed(&b, &t, &agent, false).await;
        b.test_execute(&format!(
            "UPDATE cirislens.federation_keys SET valid_until = '2020-01-01T00:00:00+00:00' \
             WHERE key_id = '{producer}'"
        ))
        .await;
        bodies::i967_refused_with_reason(&b, &agent, &row).await;
        eprintln!("i967_postgres: RAN");
    }

    on_every_backend!(i970, |b, _t| {
        bodies::i970_no_basis_from_any_claimant(&b).await;
    });

    on_every_backend!(i972, |b, t| {
        bodies::i972_the_subject_of_the_target_files(&b, &t).await;
    });

    on_every_backend!(i973, |b, t| {
        bodies::i973_a_digest_named_subject(&b, &t).await;
    });

    // I971 — two stores of one backend kind.
    #[tokio::test(flavor = "multi_thread")]
    async fn i971_memory() {
        let a = crate::store::memory::MemoryBackend::new();
        let b = crate::store::memory::MemoryBackend::new();
        let t = tag("i971m");
        let na = bodies::signing_node(&a, &format!("{t}a")).await;
        a.set_node_key_id(&na.id);
        bodies::i971_the_tombstone_delivered(&a, &b, &na, &t).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i971_sqlite() {
        use crate::store::Backend as _;
        let a = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        a.run_migrations().await.unwrap();
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let t = tag("i971s");
        let na = bodies::signing_node(&a, &format!("{t}a")).await;
        a.set_node_key_id(&na.id);
        bodies::i971_the_tombstone_delivered(&a, &b, &na, &t).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i971_postgres() {
        use crate::store::Backend as _;
        let (Some(da), Some(db)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn())
        else {
            eprintln!("i971 postgres: no base DSN — SKIPPED");
            return;
        };
        let a = crate::store::postgres::PostgresBackend::connect(&da)
            .await
            .unwrap();
        a.run_migrations().await.unwrap();
        let b = crate::store::postgres::PostgresBackend::connect(&db)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let t = tag("i971p");
        let na = bodies::signing_node(&a, &format!("{t}a")).await;
        a.set_node_key_id(&na.id);
        bodies::i971_the_tombstone_delivered(&a, &b, &na, &t).await;
        eprintln!("i971_postgres: RAN");
    }

    // I969 — V196 over v57-shaped rows (the SQL backends; memory never held
    // one: its erasure row is subject-free from birth, I966).
    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i969_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations_through(195).await.unwrap();
        let t = tag("i969s");
        let node = bodies::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        let agent = format!("{t}-agent");
        let (v57, notice, v58) = bodies::i969_seed(&b, &node.id, &agent).await;
        // A pre-v57 silo row naming its agent (written after the emitter
        // above, so the rehome has not moved it).
        b.test_execute(&format!(
            "INSERT INTO hard_case_events \
                (event_id, kind, target_key_id, subject_key_id, detail, emitted_at) \
             VALUES ('{t}-silo', 'trace_erasure', '{agent}', NULL, \
                     '{{\"agent_id_hash\":\"{agent}\"}}', '2026-01-02T03:04:05+00:00')"
        ))
        .await;
        b.run_migrations().await.unwrap();
        bodies::i969_after_v196(&b, &v57, &notice, &v58, &agent).await;
        use crate::federation::FederationDirectory as _;
        assert!(
            b.list_hard_case_events(crate::federation::hard_case::HardCaseFilter::default())
                .await
                .unwrap()
                .iter()
                .all(|e| e.event_id != format!("{t}-silo")),
            "I969: the pre-v57 silo row naming its agent is gone"
        );
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i969_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("i969 postgres: no base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations_through(195).await.unwrap();
        let t = tag("i969p");
        let node = bodies::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        let agent = format!("{t}-agent");
        let (v57, notice, v58) = bodies::i969_seed(&b, &node.id, &agent).await;
        b.test_execute(&format!(
            "INSERT INTO cirislens.hard_case_events \
                (event_id, kind, target_key_id, subject_key_id, detail, emitted_at) \
             VALUES ('{t}-silo', 'trace_erasure', '{agent}', NULL, \
                     '{{\"agent_id_hash\":\"{agent}\"}}'::jsonb, '2026-01-02T03:04:05+00:00')"
        ))
        .await;
        b.run_migrations().await.unwrap();
        bodies::i969_after_v196(&b, &v57, &notice, &v58, &agent).await;
        use crate::federation::FederationDirectory as _;
        assert!(
            b.list_hard_case_events(crate::federation::hard_case::HardCaseFilter::default())
                .await
                .unwrap()
                .iter()
                .all(|e| e.event_id != format!("{t}-silo")),
            "I969: the pre-v57 silo row naming its agent is gone"
        );
        eprintln!("i969_postgres: RAN");
    }

    // I974 — the Engine door end to end: the node's own signer.
    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i974_sqlite() {
        let signer = crate::federation::tier_ingest::test_support::local_signer(
            "i974-node-key-0123456789abcdefghijklmnop",
        );
        let engine = crate::Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine");
        engine
            .register_self_federation_key(
                crate::federation::types::identity_type::NODE,
                "ref",
                None,
                serde_json::json!({}),
                vec![],
            )
            .await
            .expect("register the node key");
        let b = engine.sqlite_backend().expect("sqlite").clone();
        let t = tag("i974s");
        i974_body(&engine, b.as_ref(), &t).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i974_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("i974 postgres: no base DSN — SKIPPED");
            return;
        };
        let signer = crate::federation::tier_ingest::test_support::local_signer(
            "i974-node-key-0123456789abcdefghijklmnop",
        );
        let engine = crate::Engine::with_signer(signer, &dsn)
            .await
            .expect("engine");
        engine
            .register_self_federation_key(
                crate::federation::types::identity_type::NODE,
                "ref",
                None,
                serde_json::json!({}),
                vec![],
            )
            .await
            .expect("register the node key");
        let b = engine.postgres_backend().expect("postgres").clone();
        let t = tag("i974p");
        i974_body(&engine, b.as_ref(), &t).await;
        eprintln!("i974_postgres: RAN");
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn i974_body<B>(engine: &crate::Engine, b: &B, t: &str)
    where
        B: crate::federation::attestation_admit::AttestationStore
            + crate::derived::DerivedSchema
            + crate::store::Backend
            + Sync,
    {
        let agent = format!("{t}-agent");
        let row_id = bodies::detected(b, t, &agent, &format!("{t}-trace")).await;
        let summary = engine
            .delete_traces_for_agent_id_hash(&agent)
            .await
            .expect("I974: the Engine's DSAR door");
        assert_eq!(summary.detection_events_tombstoned, 1, "I974: erased");
        assert!(b.get_attestation(&row_id).await.unwrap().is_none());
        let notice = b
            .purge_tombstoned("attestation", &row_id)
            .await
            .unwrap()
            .expect("I974: tombstoned");
        let header = b.purge_execution(&notice).await.unwrap().unwrap();
        let cited = crate::federation::subject_erasure::ErasureNotice::parse(
            &serde_json::from_str(&header.notice_jcs).unwrap(),
        )
        .unwrap();
        let w = b
            .get_attestation(&cited.withdraws_attestation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            w.attestation_type,
            crate::federation::types::attestation_type::WITHDRAWS
        );
        assert_eq!(
            w.attesting_key_id,
            format!("{t}-lens"),
            "I974: the producer's withdraws"
        );
        // The key-scoped Engine door.
        let agent2 = format!("{t}-agent-k");
        let row2 = bodies::detected(b, &format!("{t}k"), &agent2, &format!("{t}-trace-k")).await;
        // The one-key door (the Python surface calls the store's door).
        b.delete_traces_for_agent(&agent2, &format!("{agent2}-signer"), false)
            .await
            .expect("I974: the one-key door");
        assert!(b.get_attestation(&row2).await.unwrap().is_none());
    }
}
