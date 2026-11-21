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

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::attestation_admit::AttestationStore;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::silo_projection::{check_projection_rebuild, SiloProjection};
    use crate::federation::subject_erasure::{self as se, ErasureNotice};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type, Attestation};
    use crate::federation::{Error, FederationDirectory};

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
        // v62.0.0 (E2-fix7) — a test key seeds from the first 32 bytes of its
        // name, and two tags may differ only in their last character
        // (`{tag}a` / `{tag}b`): a short digest of the tag leads the alias.
        let lead = {
            use sha2::Digest as _;
            hex::encode(&sha2::Sha256::digest(tag.as_bytes())[..4])
        };
        let alias = format!("{lead}-node-key-{tag}-0123456789abcdef")
            .replace('_', "-")
            .to_lowercase();
        // v62.0.0 (JSON cut, E7) — the node's key is an edition-2 record; its
        // id is the identity-ref of the composite `local_signer(alias)` signs
        // with (E0: `signing_key` follows `local_signer`'s alias).
        let id = e2::put_key(b, &alias, &[identity_type::NODE]).await;
        Node { id, alias }
    }

    pub(crate) fn detection(trace: &str, signer: &str) -> crate::derived::DetectionEvent {
        crate::derived::DetectionEvent {
            detection_id: uuid::Uuid::new_v4(),
            trace_id: trace.to_owned(),
            body_sha256: vec![7u8; 32],
            // v62.0.0 (JSON cut, E7) — a detector whose `detection:{detector}`
            // family is registered (P8's edition-2 producer refuses the rest).
            detector: "hash_chain_integrity".into(),
            severity: crate::derived::DetectionSeverity::Warning,
            cohort_cell: serde_json::json!({"agent_role": "x"}),
            conformity_variant: crate::derived::ConformityVariant::Numeric,
            // v62.0.0 (P8-fix17, pass 4e) — a FRACTIONAL score, as production
            // detections carry: a non-integral body real is a tag-4 decimal
            // (`0.25` → `4([-2, 25])`), which Verify 23.3.2's `ceg-value` admits
            // (23.3.1 refused it, so P8-fix12 had rounded this to 1).
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

    /// v62.0.0 (JSON cut, E7; P8) — the detector seed of `tag`'s detections.
    pub(crate) fn detector_seed(tag: &str) -> String {
        role_seed("lens", tag)
    }

    /// v62.0.0 (JSON cut, E7) — a test seed for `role` under `tag`, distinct
    /// in its FIRST 32 BYTES (a test signer seeds from those alone): the role,
    /// then the tag's unique tail. `{tag}-lens` and `{tag}-root` shared their
    /// first 32 bytes, so the detector WAS the root, and its confers edge read
    /// as a self-loop charter.
    pub(crate) fn role_seed(role: &str, tag: &str) -> String {
        let tail = &tag[tag.len().saturating_sub(26)..];
        format!("{role}-{tail}")
    }

    /// v62.0.0 (JSON cut, E7; P8; RT-fix1) — `det` may state `detection:*`:
    /// the ROOTED trust root at `tag`'s root seed (W1b's
    /// `fixture_trust_root`, through the shared conferral fixture
    /// `admission::r2_test_support::confer_scope_from_trusted_root`: the
    /// bundle in force, an `infrastructure` community founded by its holders,
    /// the charter, THIS node's acceptance) confers `infra:detect` on `det`,
    /// with the detector's own voice and, for a machine detector, its bound
    /// owner's. The twin of P4's
    /// `edition2::standing_invariants::conferred_detector_body`; standing is
    /// never a self-declared type.
    ///
    /// RT-fix1: the earlier body chartered a bare `node` KEY root by hand. A
    /// key-arm root is as attested as its holder's custody evidence (CC
    /// 4.2.2.1), which no fixture key carries, so its grant rooted nowhere and
    /// every detection was held. The shared fixture returns only once
    /// `capability_roots_to_trusted_root(node, det, infra:detect)` roots at
    /// the root, so a conferral that confers nothing stops here.
    pub(crate) async fn confer_detect<B>(b: &B, tag: &str, det: &str)
    where
        B: FederationDirectory,
    {
        let node_kid = b
            .node_key_id()
            .expect("the runner sets this node's key before a detection");
        crate::federation::admission::r2_test_support::confer_scope_from_trusted_root(
            b,
            &node_kid,
            &role_seed("root", tag),
            det,
            crate::federation::types::delegation_scope::INFRA_DETECT,
        )
        .await;
    }

    /// v62.0.0 (JSON cut, E7; P8) — a conferred detector (`detector_seed`,
    /// an `agent` key), a held trace of `agent`, and its EDITION-2 detection
    /// (`detection_row::state_detection`): the node-computed row id.
    pub(crate) async fn detected<B>(b: &B, tag: &str, agent: &str, trace: &str) -> String
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend,
    {
        let det = detector_seed(tag);
        e2::put_key(b, &det, &[identity_type::AGENT]).await;
        detected_by(b, tag, agent, trace, &det).await
    }

    /// [`detected`] by an existing key `det` (a seed).
    pub(crate) async fn detected_by<B>(
        b: &B,
        tag: &str,
        agent: &str,
        trace: &str,
        det: &str,
    ) -> String
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend,
    {
        confer_detect(b, tag, det).await;
        b.insert_trace_events_batch(&[
            crate::federation::silo_projection_invariants::bodies::trace_row(trace, agent),
        ])
        .await
        .unwrap();
        let mut ev = detection(trace, &e2::kid(det));
        ev.ts = crate::federation::admission::truncate_to_substrate_resolution(
            chrono::Utc::now() - chrono::Duration::minutes(2),
        );
        crate::derived::detection_row::state_detection(b, &ts::local_signer(det), &ev)
            .await
            .expect("the conferred detector states its detection")
    }

    /// v62.0.0 (JSON cut, E7; P8) — `seed`'s `withdraws` of `target` as an
    /// edition-2 statement (`subject_erasure::withdraws_statement_parts`),
    /// through the statement door: its row id, or the door's refusal.
    pub(crate) async fn put_withdraws_as<B>(
        b: &B,
        seed: &str,
        target: &Attestation,
    ) -> Result<String, Error>
    where
        B: FederationDirectory + ?Sized,
    {
        let (sub, family, payload) =
            se::withdraws_statement_parts(target, &e2::kid(seed), e2::ms(chrono::Utc::now()))?;
        let st = ciris_verify_core::edition2::sign_row_statement(
            &e2::signing_key(seed),
            &e2::kid(seed),
            &sub,
            attestation_type::WITHDRAWS,
            &family,
            &payload,
            vec![],
        )
        .expect("sign the withdraws");
        crate::federation::edition2::ingest::put_statement(
            b,
            &st,
            None,
            crate::federation::edition2::ingest::INGEST_TIER,
        )
        .await?;
        Ok(crate::federation::edition2::names::RowId::of_statement(&st)
            .expect("a row statement")
            .hex())
    }

    /// v62.0.0 (JSON cut, E7; P8) — the producer `det` states its erasure
    /// withdraws for every detection row of `agent` it produced (the store
    /// door holds no signer: the producer states first).
    pub(crate) async fn state_producer_withdraws<B>(
        b: &B,
        det: &str,
        agent: &str,
        signing_key_id: Option<&str>,
    ) where
        B: AttestationStore,
    {
        se::state_erasure_withdraws(b, &ts::local_signer(det), agent, signing_key_id)
            .await
            .expect("the producer states its withdraws");
    }

    /// The trace_erasure hard case rows, as recorded.
    async fn erasure_events<B: FederationDirectory>(
        b: &B,
    ) -> Vec<crate::federation::HardCaseEvent> {
        b.list_hard_case_events(crate::federation::hard_case::HardCaseFilter {
            kind: Some(crate::federation::hard_case::kind::TRACE_ERASURE.to_owned()),
            since: None,
            emitter_key_id: None,
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
        // v62.0.0 (JSON cut, E7; P8) — the same conferred detector states it.
        let mut d = detection(
            &format!("{tag}-trace-unheld"),
            &e2::kid(&detector_seed(tag)),
        );
        d.ts = crate::federation::admission::truncate_to_substrate_resolution(
            chrono::Utc::now() - chrono::Duration::minutes(2),
        );
        let unheld = crate::derived::detection_row::state_detection(
            b,
            &ts::local_signer(&detector_seed(tag)),
            &d,
        )
        .await
        .expect("the conferred detector states its detection");
        let row = b.get_attestation(&unheld).await.unwrap().unwrap();
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
        assert_eq!(producer, e2::kid(&detector_seed(tag)), "I966: the detector");
        // v62.0.0 (P8) — the producer states its withdraws; the door cites it.
        state_producer_withdraws(b, &detector_seed(tag), &agent, None).await;

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
        assert!(
            e2::carried_statement(&w).is_some(),
            "I966: the producer's own edition-2 statement"
        );
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
        state_producer_withdraws(
            b,
            &detector_seed(&format!("{tag}k")),
            &agent2,
            Some(&signer_key),
        )
        .await;
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
    /// v62.0.0 (JSON cut, E7; P8) — the seed: an edition-2 detection of
    /// `agent`'s trace and, when `voluntary`, its producer's own withdraws
    /// statement already held. Returns `(row, detector seed, withdraws id)`.
    pub(crate) async fn i967_seed<B>(
        b: &B,
        tag: &str,
        agent: &str,
        voluntary: bool,
    ) -> (String, String, Option<String>)
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend + Sync,
    {
        let row_id = detected(b, tag, agent, &format!("{tag}-trace")).await;
        let det = detector_seed(tag);
        let wid = if voluntary {
            let target = b.get_attestation(&row_id).await.unwrap().unwrap();
            Some(
                put_withdraws_as(b, &det, &target)
                    .await
                    .expect("I967: the producer retracts its own row"),
            )
        } else {
            None
        };
        (row_id, det, wid)
    }

    /// The row is refused with `reason`, left in place, counted; nothing is
    /// tombstoned.
    pub(crate) async fn i967_refused_with_reason<B>(b: &B, agent: &str, row_id: &str, reason: &str)
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend + Sync,
    {
        let summary = b.delete_traces_for_agent_id_hash(agent).await.unwrap();
        assert_eq!(summary.trace_events, 1, "I967: the trace corpus goes");
        assert_eq!(
            summary.detection_events_tombstoned, 0,
            "I967 {reason}: the row is not erased"
        );
        assert_eq!(
            summary.detection_rows_refused,
            vec![se::ErasureRefusal {
                record_id: format!("attestation:{row_id}"),
                reason: reason.to_owned(),
            }],
            "I967: refused WITH a reason, named in the summary"
        );
        assert!(
            b.get_attestation(row_id).await.unwrap().is_some(),
            "I967 {reason}: left in place"
        );
        assert!(b
            .purge_tombstoned("attestation", row_id)
            .await
            .unwrap()
            .is_none());
        let events = erasure_events(b).await;
        assert!(
            !events.is_empty()
                && events
                    .iter()
                    .all(|e| e.detail["detection_rows_refused"] == 1),
            "I967 {reason}: counted: {events:?}"
        );
        check_projection_rebuild(b, SiloProjection::DetectionEvents)
            .await
            .expect("I967: rebuild");
    }

    /// v62.0.0 (JSON cut, E7; P8) — the two refusals, each with its reason:
    /// a live producer that has not STATED its withdraws (the door holds no
    /// signer and never plans an unsigned row), and a producer key the host
    /// no longer holds live (ended by its own revocation, after the
    /// detection's instant).
    pub(crate) async fn i967_refused_with_a_reason<B>(b: &B, tag: &str)
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend + Sync,
    {
        let agent = format!("{tag}-agent-u");
        let (row, _, _) = i967_seed(b, &format!("{tag}u"), &agent, false).await;
        i967_refused_with_reason(b, &agent, &row, se::token::PRODUCER_WITHDRAWS_UNSTATED).await;

        let agent = format!("{tag}-agent-x");
        let (row, det, _) = i967_seed(b, &format!("{tag}x"), &agent, false).await;
        let after = e2::ms(chrono::Utc::now() - chrono::Duration::minutes(1));
        crate::federation::edition2::ingest::put_statement(
            b,
            &e2::key_revocation(&det, &det, Some(after)),
            None,
            crate::federation::edition2::ingest::INGEST_TIER,
        )
        .await
        .expect("I967: the producer key ends itself");
        i967_refused_with_reason(b, &agent, &row, se::token::PRODUCER_KEY_NOT_HELD).await;
    }

    /// A producer withdraws already held is the authority: reused, not doubled.
    pub(crate) async fn i967_a_held_producer_withdraws_is_reused<B>(b: &B, tag: &str)
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend + Sync,
    {
        let agent = format!("{tag}-agent-v");
        let (row_id, det, wid) = i967_seed(b, &format!("{tag}v"), &agent, true).await;
        let wid = wid.expect("voluntary");
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
        assert_eq!(cited.withdraws_attestation_id, wid, "I967: the held one");
        let mine = b
            .list_attestations_referencing(&row_id)
            .await
            .unwrap()
            .into_iter()
            .filter(|w| w.attesting_key_id == e2::kid(&det))
            .count();
        assert_eq!(mine, 1, "I967: one producer withdraws, never two");
    }

    // ── I968 ──────────────────────────────────────────────────────────────
    /// v62.0.0 (JSON cut, E7; P8) — the carve-out on edition 2: a `withdraws`
    /// of the adverse detection row by the scored agent's own key (the rule-2
    /// party) or by another node (the rule-3 proxy) is refused at the
    /// statement door, and no erasing authority appears. (The earlier-form
    /// standing rows, a JSON canonical binding and a `delegates_to` from a
    /// canonical subject registered as a key, have no edition-2 form: a
    /// canonical subject holds no key.)
    pub(crate) async fn i968_the_carve_out_stays<B>(b: &B, tag: &str)
    where
        B: AttestationStore + crate::derived::DerivedSchema + crate::store::Backend + Sync,
    {
        let agent = format!("{tag}-agent");
        let row_id = detected(b, tag, &agent, &format!("{tag}-trace")).await;
        let target = b.get_attestation(&row_id).await.unwrap().unwrap();
        let agent_key = signing_node_as(b, &format!("{tag}ag"), identity_type::AGENT).await;
        let node = signing_node(b, &format!("{tag}n")).await;
        for (rule, seed) in [("rule 2", &agent_key.alias), ("rule 3", &node.alias)] {
            assert!(
                put_withdraws_as(b, seed, &target).await.is_err(),
                "I968 {rule}: no subject-authority path reaches a detection row"
            );
        }
        assert!(
            se::erasing_withdraws(b, &target).await.unwrap().is_none(),
            "I968: no erasing authority"
        );
        assert!(b.get_attestation(&row_id).await.unwrap().is_some());
    }

    /// [`signing_node`] with another role.
    pub(crate) async fn signing_node_as<B>(b: &B, tag: &str, role: &str) -> Node
    where
        B: FederationDirectory + ?Sized,
    {
        // v62.0.0 (round 6, E7) — as [`signing_node`]: distinct in the first
        // 32 bytes (`role` is a short identity type, at most 5 bytes).
        let alias = role_seed(role, tag).replace('_', "-").to_lowercase();
        let id = e2::put_key(b, &alias, &[role]).await;
        Node { id, alias }
    }

    // ── I970 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i970_no_basis_from_any_claimant<D>(d: &D)
    where
        D: FederationDirectory + Sync,
    {
        use crate::federation::takedown_tombstone::{self as td, token};
        let dir = d.as_dyn_directory();
        let producer = "i970-producer-0123456789abcdefghij";
        let subject_seed = "i970-subject-0123456789abcdefghijk";
        // v62.0.0 (JSON cut, E7) — keys are named by their identity-refs.
        let stranger = &e2::kid("i970-stranger-0123456789abcdefghij");
        ts::register_hybrid_key(dir, stranger).await;
        let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            format!("i970-{}", uuid::Uuid::new_v4()).as_bytes(),
        ));
        crate::federation::doors_takedown_invariants::bodies::establish(
            dir,
            producer,
            subject_seed,
            &sha,
        )
        .await;
        let subject = &e2::kid(subject_seed);
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
        e2::put_key(b_, &node_a.alias, &[identity_type::NODE]).await;
        // v62.0.0 (JSON cut, E7; P8) — one conferred detector on both nodes;
        // its ONE edition-2 detection statement (naming the agent's subject)
        // reaches both through the statement door, the same bytes.
        let agent = format!("{tag}-agent");
        let trace = format!("{tag}-trace");
        let det = detector_seed(tag);
        let mut d = detection(&trace, &e2::kid(&det));
        d.ts = crate::federation::admission::truncate_to_substrate_resolution(
            chrono::Utc::now() - chrono::Duration::minutes(2),
        );
        let subject = se::agent_subject(&agent).unwrap();
        let (sub, family, payload) =
            crate::derived::detection_row::detection_statement_parts(&d, Some(&subject))
                .expect("the detection's parts");
        let detection_bytes = ciris_verify_core::edition2::sign_row_statement(
            &e2::signing_key(&det),
            &e2::kid(&det),
            &sub,
            attestation_type::SCORES,
            &family,
            &payload,
            vec![],
        )
        .expect("sign the detection");
        let row_id = crate::federation::edition2::names::RowId::of_statement(&detection_bytes)
            .expect("a row statement")
            .hex();
        for s in [a, b_] {
            e2::put_key(s, &det, &[identity_type::AGENT]).await;
            confer_detect(s, tag, &det).await;
            s.insert_trace_events_batch(&[
                crate::federation::silo_projection_invariants::bodies::trace_row(&trace, &agent),
            ])
            .await
            .unwrap();
            crate::federation::edition2::ingest::put_statement(
                s,
                &detection_bytes,
                None,
                crate::federation::edition2::ingest::INGEST_TIER,
            )
            .await
            .expect("I971: the detection is admitted");
        }
        let _ = node_a;
        state_producer_withdraws(a, &det, &agent, None).await;
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

        // The producer's withdraws (its own edition-2 statement, the bytes A
        // holds) replicates to B through B's statement door.
        let cited = ErasureNotice::parse(&bundle.notice.envelope).unwrap();
        let w = a
            .get_attestation(&cited.withdraws_attestation_id)
            .await
            .unwrap()
            .unwrap();
        let w_bytes = e2::carried_statement(&w).expect("I971: the withdraws is a statement");
        crate::federation::edition2::ingest::put_statement(
            b_,
            &w_bytes,
            None,
            crate::federation::edition2::ingest::INGEST_TIER,
        )
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
        let again = crate::federation::edition2::ingest::put_statement(
            b_,
            &detection_bytes,
            None,
            crate::federation::edition2::ingest::INGEST_TIER,
        )
        .await;
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

    /// v62.0.0 (JSON cut, E7) — a flipped row through the one entry.
    async fn put(dir: &dyn FederationDirectory, row: Attestation) -> Result<(), Error> {
        e2::put_signed(dir, &row).await.map(|_| ())
    }

    /// v62.0.0 (JSON cut, E7; CC 2.7, wave GC1) — the row through the one
    /// entry is HELD: kept, concluding nothing until its standing arrives
    /// (`StatementOutcome::Pending`). GC1 turned the reconsideration door's
    /// refusals into fold holds; the reason tokens are a G-wave's to pin.
    async fn put_held(dir: &dyn FederationDirectory, row: Attestation) -> bool {
        matches!(
            e2::put_signed(dir, &row).await,
            Ok(crate::federation::edition2::ingest::StatementOutcome::Pending { .. })
        )
    }

    /// v62.0.0 (round 6, E7; CC 2.7.3) — the row concludes nothing: HELD
    /// (`Pending`) or refused outright by an earlier gate, and not live under
    /// its row id. For an arm more than one door can stop (a filing naming a
    /// community that is not the target's, which also names a room the filer
    /// is no member of): the property is that it does not land.
    async fn put_not_landed(dir: &dyn FederationDirectory, row: Attestation) -> bool {
        let id = e2::rid(&row);
        let out = e2::put_signed(dir, &row).await;
        let stopped = matches!(
            out,
            Ok(crate::federation::edition2::ingest::StatementOutcome::Pending { .. }) | Err(_)
        );
        stopped && dir.get_attestation(&id).await.unwrap().is_none()
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
        // v62.0.0 (JSON cut, E7) — keys and the room by their identity-refs.
        let k = |n: &str| e2::kid(&format!("i972-{n}-{tag}-0123456789abcdefghij"));
        let (moderator, subject, stranger) = (k("mod"), k("subj"), k("stranger"));
        let comm_s = format!("i972-comm-{tag}");
        crate::federation::doors_takedown_invariants::bodies::community_of(
            dir, &comm_s, &moderator,
        )
        .await;
        let comm = e2::kid(&comm_s);
        for key in [&subject, &stranger] {
            ts::register_hybrid_key(dir, key).await;
        }
        // The prior action: the moderator's row about `subject` in the room.
        let target_row = scores_row(
            &format!("i972-target-{tag}"),
            &moderator,
            serde_json::json!({
                "dimension": "moderation:harassment:v1",
                "score": -1.0, "confidence": 1.0, "community_id": comm,
            }),
            &[&subject],
            // The subject is no member of the room: a federation-scope
            // row naming the room carries the action (CC 4.5.5's target).
            "federation",
        );
        let target = target_row.attestation_id.clone();
        put(dir, target_row).await.expect("I972: the prior action");
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
        assert!(
            put_held(
                dir,
                reconsideration(
                    &format!("i972-r2-{tag}"),
                    &stranger,
                    &target,
                    serde_json::json!({}),
                    &[&stranger],
                ),
            )
            .await,
            "I972: a self-declared subject is no standing: held (CC 2.7, GC1), concluding nothing"
        );
        // (3) the subject RULES: refused — the ruling stays with review-holders.
        assert!(
            put_held(
                dir,
                reconsideration(
                    &format!("i972-r3-{tag}"),
                    &subject,
                    &target,
                    serde_json::json!({"outcome": "reversed"}),
                    &[],
                ),
            )
            .await,
            "I972: the subject cannot rule: held (CC 2.7, GC1), concluding nothing"
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
        assert!(
            put_not_landed(
                dir,
                reconsideration(
                    &format!("i972-r5-{tag}"),
                    &subject,
                    &target,
                    serde_json::json!({"community_id": e2::kid(&format!("{comm_s}-other"))}),
                    &[],
                ),
            )
            .await,
            "I972: a filing naming another community concludes nothing (held or refused)"
        );
        // (6) a target not held here: the subject arm is empty.
        assert!(
            put_held(
                dir,
                reconsideration(
                    &format!("i972-r6-{tag}"),
                    &subject,
                    // A row id no node holds (the door names targets by row id).
                    &hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                        format!("i972-absent-{tag}").as_bytes(),
                    )),
                    serde_json::json!({}),
                    &[&subject],
                ),
            )
            .await,
            "I972: no held target, no subject standing: held (CC 2.7, GC1), concluding nothing"
        );
        // (7) a licence target (v60.0.0, CIRISPersist#1036 item 5): the
        // licensee is the subject that files — its own `withdraws` against
        // the licence is refused, so `reconsideration:{grounds}` is its
        // contest path (CC 2.4.1.1; I1218 drives it end to end).
        let licence = ts::bare_attestation(
            "i972-licence",
            &moderator,
            &subject,
            &serde_json::json!({"dimension": "licensure:board:v1"}),
        );
        assert_eq!(
            crate::federation::admission::reconsideration_target_subjects(dir, &stranger, &licence)
                .await
                .unwrap(),
            std::iter::once(subject.clone()).collect(),
            "I972: a licence's licensee has standing to file"
        );
    }

    pub(crate) async fn i973_a_digest_named_subject<D>(d: &D, tag: &str)
    where
        D: FederationDirectory + Sync,
    {
        let dir = d.as_dyn_directory();
        // v62.0.0 (JSON cut, E7) — keys and the room by their identity-refs.
        let k = |n: &str| e2::kid(&format!("i973-{n}-{tag}-0123456789abcdefghij"));
        let (moderator, subject, other) = (k("mod"), k("subj"), k("other"));
        let comm_s = format!("i973-comm-{tag}");
        crate::federation::doors_takedown_invariants::bodies::community_of(
            dir, &comm_s, &moderator,
        )
        .await;
        let comm = e2::kid(&comm_s);
        for key in [&subject, &other] {
            ts::register_hybrid_key(dir, key).await;
        }
        let rec = dir.lookup_public_key(&subject).await.unwrap().unwrap();
        let digest = crate::federation::key_digest::Sha256Ed25519Raw::from_pubkey_base64(
            &rec.pubkey_ed25519_base64,
        )
        .unwrap()
        .to_hex();
        let target_row = scores_row(
            &format!("i973-target-{tag}"),
            &moderator,
            serde_json::json!({
                "dimension": "moderation:harassment:v1",
                "score": -1.0, "confidence": 1.0, "community_id": comm,
                "subject_sha256_ed25519_raw": digest,
            }),
            &[],
            "community",
        );
        let target = target_row.attestation_id.clone();
        put(dir, target_row)
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
        assert!(
            put_held(
                dir,
                reconsideration(
                    &format!("i973-r2-{tag}"),
                    &other,
                    &target,
                    serde_json::json!({}),
                    &[],
                ),
            )
            .await,
            "I973: any other filer is refused: held (CC 2.7, GC1), concluding nothing"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
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
        let node = bodies::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
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

    on_every_backend!(i967_refused, |b, t| {
        let node = bodies::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        bodies::i967_refused_with_a_reason(&b, &t).await;
    });

    on_every_backend!(i968, |b, t| {
        let node = bodies::signing_node(&b, &t).await;
        b.set_node_key_id(&node.id);
        bodies::i968_the_carve_out_stays(&b, &t).await;
    });

    on_every_backend!(i970, |b, _t| {
        bodies::i970_no_basis_from_any_claimant(&b).await;
    });

    on_every_backend!(i972, |b, t| {
        bodies::i972_the_subject_of_the_target_files(&b, &t).await;
    });

    on_every_backend!(i973, |b, t| {
        bodies::i973_a_digest_named_subject(&b, &t).await;
    });

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
        // v62.0.0 (JSON cut, E7) — B's node key too (its detector conferral
        // is accepted by B).
        let nb = bodies::signing_node(&b, &format!("{t}b")).await;
        b.set_node_key_id(&nb.id);
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
        // v62.0.0 (JSON cut, E7) — B's node key too (its detector conferral
        // is accepted by B).
        let nb = bodies::signing_node(&b, &format!("{t}b")).await;
        b.set_node_key_id(&nb.id);
        bodies::i971_the_tombstone_delivered(&a, &b, &na, &t).await;
        eprintln!("i971_postgres: RAN");
    }

    // I974 — the Engine door end to end: the node's own signer.
    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i974_sqlite() {
        let signer = crate::federation::tier_ingest::test_support::local_signer(I974_NODE);
        let engine = crate::Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine");
        let b = engine.sqlite_backend().expect("sqlite").clone();
        // v62.0.0 (JSON cut, E7) — the node's key is an edition-2 record, named
        // by its identity-ref (the JSON self-registration door is shut).
        let node = crate::federation::edition2::fixture_switch::put_key(
            b.as_ref(),
            I974_NODE,
            &[crate::federation::types::identity_type::NODE],
        )
        .await;
        b.set_node_key_id(&node);
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
        let signer = crate::federation::tier_ingest::test_support::local_signer(I974_NODE);
        let engine = crate::Engine::with_signer(signer, &dsn)
            .await
            .expect("engine");
        let b = engine.postgres_backend().expect("postgres").clone();
        // v62.0.0 (JSON cut, E7) — the node's key is an edition-2 record, named
        // by its identity-ref (the JSON self-registration door is shut).
        let node = crate::federation::edition2::fixture_switch::put_key(
            b.as_ref(),
            I974_NODE,
            &[crate::federation::types::identity_type::NODE],
        )
        .await;
        b.set_node_key_id(&node);
        let t = tag("i974p");
        i974_body(&engine, b.as_ref(), &t).await;
        eprintln!("i974_postgres: RAN");
    }

    /// The I974 engine's node key (a seed), also its detector.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    const I974_NODE: &str = "i974-node-key-0123456789abcdefghijklmnop";

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn i974_body<B>(engine: &crate::Engine, b: &B, t: &str)
    where
        B: crate::federation::attestation_admit::AttestationStore
            + crate::derived::DerivedSchema
            + crate::store::Backend
            + Sync,
    {
        // v62.0.0 (JSON cut, E7; P8) — the detector is THIS engine's node key,
        // so the Engine's door states the producer's withdraws itself.
        let det = I974_NODE;
        let agent = format!("{t}-agent");
        let row_id = bodies::detected_by(b, t, &agent, &format!("{t}-trace"), det).await;
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
            crate::federation::edition2::fixture_switch::kid(det),
            "I974: the producer's withdraws"
        );
        // The key-scoped Engine door.
        let agent2 = format!("{t}-agent-k");
        let row2 =
            bodies::detected_by(b, &format!("{t}k"), &agent2, &format!("{t}-trace-k"), det).await;
        // The one-key door (the Python surface calls the store's door, which
        // holds no signer: the producer states first).
        bodies::state_producer_withdraws(b, det, &agent2, Some(&format!("{agent2}-signer"))).await;
        b.delete_traces_for_agent(&agent2, &format!("{agent2}-signer"), false)
            .await
            .expect("I974: the one-key door");
        assert!(b.get_attestation(&row2).await.unwrap().is_none());
    }
}
