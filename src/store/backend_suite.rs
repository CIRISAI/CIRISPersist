//! v60.0.0 (CIRISPersist#1002) — **the retired memory backend's own tests,
//! on SQLite.**
//!
//! `src/store/memory.rs` carried these tests and ran them on its in-process
//! map. With that backend retired they run on
//! [`test_backend`](super::test_backend::test_backend), the migrated in-memory
//! SQLite. A test whose property already runs on sqlite elsewhere was dropped,
//! not moved; the S5 handoff names each and its twin.

#[cfg(test)]
mod tests {
    use crate::schema::CompleteTrace;
    use crate::schema::ReasoningEventType;
    use crate::schema::{ComponentType, SchemaVersion, TraceLevel};
    use crate::store::backend::Backend;
    use crate::store::decompose::decompose;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::test_backend::test_backend;
    use crate::store::types::{TraceEventRow, TraceLlmCallRow};

    fn fixture_row(attempt_index: u32, event_type: ReasoningEventType) -> TraceEventRow {
        TraceEventRow {
            trace_id: "trace-x".into(),
            thought_id: "th-1".into(),
            task_id: None,
            step_point: None,
            event_type,
            attempt_index,
            ts: "2026-04-30T00:16:00Z".parse().unwrap(),
            agent_name: None,
            agent_id_hash: "deadbeef".into(),
            cognitive_state: None,
            trace_level: TraceLevel::Generic,
            payload: serde_json::Map::new(),
            cost_llm_calls: None,
            cost_tokens: None,
            cost_usd: None,
            signature: "AAAA".into(),
            signing_key_id: "test-key".into(),
            signature_verified: true,
            verification_source: crate::store::VerificationSource::Persist,
            schema_version: "2.7.0".into(),
            pii_scrubbed: false,
            // FSD §3.7 envelope columns: tests for the in-memory
            // dedup / idempotency surface use None — pipeline tests
            // populate them.
            original_content_hash: None,
            scrub_signature: None,
            scrub_key_id: None,
            scrub_timestamp: None,
            // v32.0.0 (#690) — no scrub ran here, so no claim is made.
            // v32.1.0 (#606) — the backend stamps this at insert.
            admitted_at: None,
            scrub_ner_ran: None,
            scrub_applied_trace_level: None,
            scrub_model_digest: None,
            // v0.3.4 deployment_profile columns. Test fixture stays
            // 2.7.0-shape (no profile) — None across the board.
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

    /// THREAT_MODEL.md AV-9 regression: two distinct agents with
    /// the same trace_id/thought_id/event_type/attempt_index/ts
    /// shape no longer collide. Pre-fix this would have silently
    /// dropped one agent's row.
    #[tokio::test]
    async fn dedup_keyed_by_agent_id_hash() {
        let backend = test_backend();
        let mut row_a = fixture_row(0, ReasoningEventType::ActionResult);
        let mut row_b = fixture_row(0, ReasoningEventType::ActionResult);
        // Same trace shape; different agent.
        row_a.agent_id_hash = "agent-a".into();
        row_b.agent_id_hash = "agent-b".into();

        let r = backend
            .insert_trace_events_batch(&[row_a, row_b])
            .await
            .unwrap();
        assert_eq!(r.inserted, 2, "distinct agents must not collide");
        assert_eq!(r.conflicted, 0);
        assert_eq!(backend.snapshot_events().len(), 2);
    }

    #[tokio::test]
    async fn intra_batch_duplicates_conflict() {
        // A batch that itself contains two rows with the same dedup
        // tuple is a bug; mirror Postgres's ON CONFLICT DO NOTHING
        // behavior.
        let backend = test_backend();
        let rows = vec![
            fixture_row(0, ReasoningEventType::ConscienceResult),
            fixture_row(0, ReasoningEventType::ConscienceResult),
        ];
        let r = backend.insert_trace_events_batch(&rows).await.unwrap();
        assert_eq!(r.inserted, 1);
        assert_eq!(r.conflicted, 1);
    }

    /// Mission category §4 "Backend parity" (placeholder for the
    /// Phase-1.4 conformance suite): a decomposed CompleteTrace lands
    /// on the in-memory SQLite test backend with the right row counts, dedup
    /// keys preserved, and llm_calls separated.
    #[tokio::test]
    async fn end_to_end_decompose_and_store() {
        let trace = CompleteTrace {
            trace_id: "trace-x-1".into(),
            thought_id: "th-1".into(),
            task_id: Some("task-1".into()),
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:15:53.123Z".parse().unwrap(),
            completed_at: "2026-04-30T00:16:12.789Z".parse().unwrap(),
            trace_level: TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            components: vec![
                crate::schema::TraceComponent {
                    component_type: ComponentType::Observation,
                    event_type: ReasoningEventType::ThoughtStart,
                    timestamp: "2026-04-30T00:15:53.123Z".parse().unwrap(),
                    data: {
                        let mut m = serde_json::Map::new();
                        m.insert("attempt_index".into(), 0.into());
                        m
                    },
                    agent_id_hash: None,
                },
                crate::schema::TraceComponent {
                    component_type: ComponentType::LlmCall,
                    event_type: ReasoningEventType::LlmCall,
                    timestamp: "2026-04-30T00:15:54.012Z".parse().unwrap(),
                    data: {
                        let mut m = serde_json::Map::new();
                        m.insert("attempt_index".into(), 0.into());
                        m.insert("handler_name".into(), "EthicalPDMA".into());
                        m.insert("service_name".into(), "OpenAICompatibleLLM".into());
                        m.insert("timestamp".into(), "2026-04-30T00:15:54.012Z".into());
                        m.insert("duration_ms".into(), serde_json::json!(900.0));
                        m.insert("status".into(), "ok".into());
                        m
                    },
                    agent_id_hash: None,
                },
                crate::schema::TraceComponent {
                    component_type: ComponentType::Action,
                    event_type: ReasoningEventType::ActionResult,
                    timestamp: "2026-04-30T00:16:12.789Z".parse().unwrap(),
                    data: {
                        let mut m = serde_json::Map::new();
                        m.insert("attempt_index".into(), 0.into());
                        m.insert("llm_calls".into(), 1.into());
                        m.insert("tokens_total".into(), 8704.into());
                        m.insert("cost_cents".into(), serde_json::json!(0.5));
                        m
                    },
                    agent_id_hash: None,
                },
            ],
            deployment_profile: None,
            cohort_scope: "federation".into(),
            cohort_target_id: None,
            signature: "AAAA".into(),
            signature_key_id: "ciris-agent-key:dead".into(),
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
            run_kind: None,
        };

        let d = decompose(&trace).expect("decompose ok");
        let backend = test_backend();

        let event_report = backend.insert_trace_events_batch(&d.events).await.unwrap();
        assert_eq!(event_report.inserted, 3);
        let llm_count = backend
            .insert_trace_llm_calls_batch(&d.llm_calls)
            .await
            .unwrap();
        assert_eq!(llm_count, 1);

        // ACTION_RESULT row carries denormalized cost.
        let snap = backend.snapshot_events();
        let action = snap
            .iter()
            .find(|e| e.event_type == ReasoningEventType::ActionResult)
            .unwrap();
        assert_eq!(action.cost_llm_calls, Some(1));
        assert_eq!(action.cost_tokens, Some(8704));
        assert!((action.cost_usd.unwrap() - 0.005).abs() < 1e-9);
    }

    // ─── FederationDirectory tests ─────────────────────────────────

    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::{Attestation, FederationDirectory, KeyRecord, SignedKeyRecord};

    /// E5-fix1 (round 3) — **a row the door did not land**, either way it
    /// can not land: REFUSED (`Err`: a check of the bytes or of the row
    /// alone) or HELD (`Pending`: v62 G0/GC1, CC 2.7.3 — the gate read OTHER
    /// rows, so its unmet condition is a fold condition, the statement is
    /// kept and nothing concludes). Standing ruling 5: the decision tables
    /// below assert the gate's verdict in whichever form the door gives it.
    /// A held row's `kind` is the refusal kind of the gate that holds with
    /// that fold reason (the gate's `fold::hold(reason, err)` pairs them);
    /// its text is the gate's own refusal text (the hold's detail).
    #[derive(Debug)]
    pub(crate) struct NotLanded {
        kind: String,
        text: String,
        refused: Option<crate::federation::Error>,
    }

    impl NotLanded {
        pub(crate) async fn of<D: FederationDirectory + ?Sized>(
            dir: &D,
            out: Result<
                crate::federation::edition2::ingest::StatementOutcome,
                crate::federation::Error,
            >,
            what: &str,
        ) -> Self {
            use crate::federation::edition2::{fold, fold::reason as r, ingest::StatementOutcome};
            match out {
                Err(e) => Self {
                    kind: e.kind().to_owned(),
                    text: e.to_string(),
                    refused: Some(e),
                },
                Ok(StatementOutcome::Pending { row_id, .. }) => {
                    let held = fold::why_held(dir, &row_id)
                        .await
                        .expect("why held")
                        .unwrap_or_else(|| panic!("{what}: Pending, yet no fold reason"));
                    let kind = match held.reason.as_str() {
                        x if x == r::gc1::DELEGATED_SCOPE_UNAUTHORIZED => {
                            "federation_delegated_scope_unauthorized".to_owned()
                        }
                        x if x == r::STEWARD_UNPROVEN => {
                            "federation_user_target_steward_binding_forbidden".to_owned()
                        }
                        x if x == r::gc1::RESERVED_PREFIX_EMITTER_MISMATCH => {
                            "federation_reserved_prefix_emitter_mismatch".to_owned()
                        }
                        x if x == r::gc6::CHARTER_SUCCESSOR_UNHELD
                            || x == r::gc6::CHARTER_RECOVERY_UNBOUND =>
                        {
                            "federation_charter_invalid".to_owned()
                        }
                        other => format!("held:{other}"),
                    };
                    Self {
                        kind,
                        text: held.detail,
                        refused: None,
                    }
                }
                Ok(landed) => panic!("{what}: the row landed: {landed:?}"),
            }
        }

        pub(crate) fn kind(&self) -> &str {
            &self.kind
        }

        /// The refusal itself, when refused (never for a held row).
        pub(crate) fn error(&self) -> Option<&crate::federation::Error> {
            self.refused.as_ref()
        }

        /// Does the refusal (or hold) name `reason` (`… ({reason}) …`, the
        /// steward-binding gate's text)?
        pub(crate) fn reason_is(&self, reason: &str) -> bool {
            self.text.contains(&format!("({reason})"))
        }
    }

    impl std::fmt::Display for NotLanded {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.text)
        }
    }

    /// v62.0.0 (JSON cut, E5) — `key_id`'s edition-2 `key:record` (seed =
    /// `key_id`), live in the store through the key door; returns the key's
    /// identity-ref, which every later read and assertion names it by. The
    /// default windows (node/agent: today − 180 days … + 365 days; others from
    /// 0, no end): every row this suite signs under the edition 2 is
    /// now-relative (`fix_attestation`), so no key here starts at a fixed date.
    /// E5-fix2 (round 6; K2-fix6 / E0-fix6, CC 2.6.1.9 / 2.7.5) — **a row put
    /// with every second-signer voice its resolved family model names**
    /// (`e2::land_delegation`: a `trust:confers` grant's delegate, a
    /// delegation's delegate and a machine delegate's owner). A row whose
    /// family names none (a score, an age row, a charter self-edge) is its
    /// author's statement alone, exactly `e2::put_signed`. The gates judge
    /// it as before; only the voices a counted row waits for are supplied
    /// (ruling 5: supply the dependency). Every suite put goes through it.
    async fn put_voiced<D: FederationDirectory + ?Sized>(
        d: &D,
        row: &Attestation,
    ) -> Result<crate::federation::edition2::ingest::StatementOutcome, crate::federation::Error>
    {
        e2::land_delegation(d, row).await.map(|(out, _)| out)
    }

    async fn put_e2_key(backend: &SqliteBackend, key_id: &str, identity_type: &str) -> String {
        e2::put_key(backend, key_id, &e2::identity_types_of(identity_type)).await
    }

    fn fix_key(key_id: &str, identity_ref: &str, scrub_key_id: &str) -> KeyRecord {
        // v9.0.0 (CC 5.3.2.4.3.1) — register REAL deterministic hybrid
        // pubkeys so the federation-tier ingest gate verifies attestations
        // signed by this key (see `tier_ingest::test_support`).
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(key_id);
        KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: identity_ref.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({"id": key_id}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            // v47.3.0 (#901, FSD §3.6) — every synthetic identity is hardware-attested.
            attestation_evidence: Some(
                crate::federation::hardware_attestation::test_support::fresh_accord_holder_evidence(
                ),
            ),
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// v9.0.0 (CC 5.3.2.4.3.1) — (re-)sign a federation-tier test
    /// attestation's envelope with its `attesting_key_id`'s deterministic
    /// hybrid key so the mandatory federation-tier ingest gate verifies
    /// it. Call AFTER any post-construction mutation of
    /// `attestation_envelope` / `attesting_key_id`. Matching pubkeys are
    /// registered via [`fix_key`].
    ///
    /// v31.0.0 (CIRISPersist#643) — delegates to
    /// [`tier_ingest::test_support::reseal`](crate::federation::tier_ingest::test_support::reseal),
    /// which ALSO re-stamps the typed-column mirror from the row's own SEVEN
    /// columns before signing (v31.0.0, CIRISPersist#658 — this said five and
    /// then listed five, omitting `attestation_id` and `attesting_key_id`; the
    /// authority is [`row_paths::ALL`](crate::federation::envelope::row_paths::ALL)).
    /// A mutation to `attestation_id` / `attesting_key_id` / `attestation_type` /
    /// `subject_key_ids` / `attested_key_id` / `cohort_scope` / `weight` is now
    /// exactly as much a re-sign trigger as a mutation to the envelope, and
    /// keeping both in one helper is what stops a fixture from re-signing half
    /// the change.
    fn resign_fix(row: &mut Attestation) {
        // v60.0.0 (#1048) — a term-bearing `delegates_to` carries a term.
        if row.attestation_type == crate::federation::types::attestation_type::DELEGATES_TO {
            crate::federation::admission::with_test_term(
                &mut row.attestation_envelope,
                row.asserted_at,
            );
        }
        crate::federation::tier_ingest::test_support::reseal(row);
    }

    fn fix_attestation(
        id: &str,
        attesting: &str,
        attested: &str,
        scrub_key_id: &str,
    ) -> Attestation {
        // v62.0.0 (JSON cut, E5) — the fixed-instant rule (E0.api v1.6): an
        // edition-2 row is signed NOW-relative (yesterday 00:00 UTC), inside
        // its node/agent signer's default key window, so no fixture key both
        // starts at a fixed date and signs now-relative rows; the earlier form
        // (held tests) keeps its fixed 2026-05-01.
        let at: chrono::DateTime<chrono::Utc> = if e2::emit_edition2() {
            let today = chrono::Utc::now()
                .date_naive()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc();
            today - chrono::Duration::days(1)
        } else {
            "2026-05-01T00:00:00Z".parse().unwrap()
        };
        let mut row = Attestation {
            attestation_id: id.into(),
            attesting_key_id: attesting.into(),
            attested_key_id: attested.into(),
            attestation_type: crate::federation::types::attestation_type::SCORES.into(),
            weight: Some(1.0),
            asserted_at: at,
            expires_at: None,
            // v2.4.0 admission gate (CIRISPersist#102 Ask 3) — `scores`
            // attestations need a versioned mechanism-descriptive
            // dimension. v62.0.0 (E5): a REGISTERED one (the edition-2 door
            // refuses open vocabulary; `identity_binding:v1` was one).
            attestation_envelope: serde_json::json!({
                "id": id,
                // v62.0.0 (E5) — the earlier form (held tests) keeps its own.
                "dimension": if e2::emit_edition2() {
                    "coherence_standing:cab:v1"
                } else {
                    "identity_binding:v1"
                },
                "score": 1.0,
                "confidence": 0.9,
            }),
            original_content_hash: "abc123".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        // v9.0.0 — sign the as-built envelope (CC 5.3.2.4.3.1).
        resign_fix(&mut row);
        row
    }

    /// v21.12.0 (CIRISPersist#530) — the repair page source surfaces ONLY
    /// the stranded rows: `tier = 'federation'` AND a suppressed
    /// (`self`/`family`) `cohort_scope`. Already-visible federation/community
    /// scopes and any local-tier row are excluded; results page in
    /// `attestation_id` ASC with a working keyset cursor. Rows are seeded
    /// straight into state — a stranded row exists precisely because it
    /// bypassed the placement machinery, so the read path must be provable
    /// against an arbitrary stored shape.
    #[tokio::test]
    async fn list_widening_candidates_filters_suppressed_scopes_530() {
        use crate::federation::types::{attestation_tier, cohort_scope};
        let be = test_backend();
        // v62.0.0 (E5) — each row's stored id is its computed row id.
        let mut rid = std::collections::BTreeMap::new();
        for (id, tier, scope) in [
            ("s-self", attestation_tier::FEDERATION, cohort_scope::SELF),
            (
                "s-family",
                attestation_tier::FEDERATION,
                cohort_scope::FAMILY,
            ),
            (
                "v-fed",
                attestation_tier::FEDERATION,
                cohort_scope::FEDERATION,
            ),
            (
                "v-comm",
                attestation_tier::FEDERATION,
                cohort_scope::COMMUNITY,
            ),
            ("l-self", attestation_tier::LOCAL, cohort_scope::SELF),
            // v39.0.0 — already widened: a `supersedes` by k530 references it
            // (pushed below), so it is NOT a candidate — the NOT EXISTS arm on
            // the SQL backends.
            ("w-self", attestation_tier::FEDERATION, cohort_scope::SELF),
        ] {
            let mut a = fix_attestation(id, "k530", "k530", "k530");
            a.tier = tier.to_string();
            a.cohort_scope = scope.to_string();
            resign_fix(&mut a);
            rid.insert(id, e2::rid(&a));
            be.plant_attestation_below_the_door(a);
        }

        {
            let mut sup = fix_attestation("w-self-widened", "k530", "k530", "k530");
            sup.attestation_type = crate::federation::types::attestation_type::SUPERSEDES.into();
            sup.attestation_envelope["references_attestation_id"] =
                serde_json::json!(rid["w-self"]);
            sup.cohort_scope = cohort_scope::COMMUNITY.to_string();
            resign_fix(&mut sup);
            be.plant_attestation_below_the_door(sup);
        }
        let ids: Vec<String> = be
            .list_widening_candidates(None, 100)
            .await
            .expect("page")
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        let mut expected = vec![rid["s-family"].clone(), rid["s-self"].clone()];
        expected.sort();
        assert_eq!(
            ids, expected,
            "only suppressed federation-tier rows, ASC by attestation_id"
        );

        // keyset cursor resumes strictly after the given id.
        let after: Vec<String> = be
            .list_widening_candidates(Some(&expected[0]), 100)
            .await
            .expect("page 2")
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(after, vec![expected[1].clone()]);
    }

    /// CIRISPersist#807 — **a row already published WIDER by other means is
    /// not awaiting anybody.**
    ///
    /// The owner-binding case CIRISServer measured: setup writes
    /// `delegates_to(owner → node)` at `self`, and the announce publishes a
    /// FRESH `delegates_to` at federation scope rather than a `supersedes`
    /// (which is correct: a `supersedes` announce would be invisible to every
    /// peer, and an edition-2 composer carries no binding body at all). The
    /// `self` row therefore never acquires a referencing `supersedes`, and the
    /// sweep reported `awaiting_actor` on every announced node, every tick,
    /// forever: "1 row(s) are stuck awaiting their author's signer" — false on
    /// an announced node, and misleading on an un-announced one.
    ///
    /// Mutation: drop the equivalent-wider arm and this goes red.
    #[tokio::test]
    async fn an_equivalently_wider_row_retires_the_candidate_807() {
        use crate::federation::types::{attestation_tier, cohort_scope};
        let be = test_backend();
        let push = |id: &str, scope: &str| {
            let mut a = fix_attestation(id, "owner", "node-a", "owner");
            a.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
            a.tier = attestation_tier::FEDERATION.to_string();
            a.cohort_scope = scope.to_string();
            resign_fix(&mut a);
            // v62.0.0 (E5) — the stored id is the computed row id.
            let id = e2::rid(&a);
            be.plant_attestation_below_the_door(a);
            id
        };
        // The `self` binding alone IS a candidate — nothing publishes it yet.
        let binding_self = push("binding-self", cohort_scope::SELF);
        let ids: Vec<String> = be
            .list_widening_candidates(None, 100)
            .await
            .expect("page")
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(
            ids,
            vec![binding_self],
            "#807: an undiscoverable row with no wider publication IS awaiting one"
        );

        // The announce: a fresh equivalent row at a discoverable scope.
        push("binding-announced", cohort_scope::FEDERATION);
        let ids: Vec<String> = be
            .list_widening_candidates(None, 100)
            .await
            .expect("page")
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert!(
            ids.is_empty(),
            "#807: the same attester has published the same claim (type, attested key and \
             dimension) at a DISCOVERABLE scope, so the `self` row is settled, not stuck. \
             Reporting it as a candidate makes `promote_consented_backlog` say \
             `awaiting_actor` on every announced node forever: {ids:?}"
        );

        // …and a DIFFERENT claim by the same attester does not retire it —
        // otherwise one announce would silence every candidate that node has.
        let other_self;
        {
            let mut a = fix_attestation("other-self", "owner", "node-b", "owner");
            a.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
            a.tier = attestation_tier::FEDERATION.to_string();
            a.cohort_scope = cohort_scope::SELF.to_string();
            resign_fix(&mut a);
            other_self = e2::rid(&a);
            be.plant_attestation_below_the_door(a);
        }
        let ids: Vec<String> = be
            .list_widening_candidates(None, 100)
            .await
            .expect("page")
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(
            ids,
            vec![other_self],
            "#807: the exclusion must match the CLAIM (attester, type, attested key, dimension) \
             — a wider row about a different subject settles nothing"
        );
    }

    // ── v17.4.0 (FSD-005 Appendix C) — scores read surface parity ──

    /// v38.0.0 (CIRISPersist#721) — **the per-key DSAR delete announces like
    /// its Art.-17 sibling.** Same fixture shape as the dsar tests below.
    #[tokio::test]
    async fn delete_traces_for_agent_announces_like_its_sibling_721() {
        use crate::federation::FederationDirectory as _;
        use crate::store::Backend as _;
        let backend = test_backend();
        // v57.0.0 (#988 item 2) — a hard_case row needs this node's key.
        crate::federation::hard_case::test_support::declare_node(&backend, "suite-test-node").await;
        backend
            .insert_trace_events_batch(&[dsar_fixture_row("agent-721", "key-721", "t-721")])
            .await
            .unwrap();
        let summary = backend
            .delete_traces_for_agent("agent-721", "key-721", false)
            .await
            .unwrap();
        assert_eq!(summary.trace_events_deleted, 1);
        let events = backend
            .list_hard_case_events(crate::federation::hard_case::HardCaseFilter::default())
            .await
            .unwrap();
        let ev = events
            .iter()
            .find(|e| e.detail["op"] == "delete_traces_for_agent")
            .expect("the deletion must be ANNOUNCED (#721)");
        assert_eq!(ev.kind, crate::federation::hard_case::kind::TRACE_ERASURE);
        assert_eq!(ev.detail["trace_events"], 1);
    }

    /// v38.0.0 (CIRISPersist#721) — **a removal is announced, attributed,
    /// and moves the serve cursor.** The two DELETE doors were the only
    /// table verbs removing served rows with no record anywhere — while
    /// their own DSAR sibling tombstoned AND emitted in one transaction.
    /// And the soft face changed the served set while the sibling key row's
    /// serve position stood still (the #707 class, third face).
    #[tokio::test]
    async fn peer_removal_is_announced_attributed_and_moves_the_cursor_721() {
        use crate::federation::FederationDirectory as _;
        let backend = test_backend();
        // v57.0.0 (#988 item 2) — a hard_case row needs this node's key.
        crate::federation::hard_case::test_support::declare_node(&backend, "suite-test-node").await;
        backend
            .add_peer_record("peer-721", "cGs=", "node", None)
            .await
            .unwrap();

        // Unattributed removal refuses — recording is not optional.
        let err = backend
            .remove_peer_record("peer-721", false, "   ", None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_invalid_argument", "{err}");

        // The soft face: announced + attributed.
        backend
            .remove_peer_record("peer-721", false, "operator rotation", Some("deleg-1"))
            .await
            .unwrap();
        let events = backend
            .list_hard_case_events(crate::federation::hard_case::HardCaseFilter::default())
            .await
            .unwrap();
        let ev = events
            .iter()
            .find(|e| e.kind == "admin_action:peer_removal")
            .expect("the removal must be ANNOUNCED (#721)");
        assert_eq!(ev.target_key_id.as_deref(), Some("peer-721"));
        assert_eq!(ev.detail["reason"], "operator rotation");
        assert_eq!(ev.detail["delegation_id"], "deleg-1");
        assert_eq!(ev.detail["hard"], false);
    }

    /// v38.7.0 (CIRISPersist#780) — **the index hashes ARE what this node
    /// advertises, and the page walk is complete.**
    ///
    /// The consumer computes `want = remote ∖ holdings`, so two things must
    /// hold or convergence breaks in opposite directions: a hash here that
    /// the serve path does not advertise leaves a row in `want` forever,
    /// and a page walk that drops an entry does the same. Both asserted —
    /// the alignment is by construction (the index hashes the bare row, not
    /// the `Served*` wrapper, so node-local `admitted_at` stays out of the
    /// digest) but "by construction" is what this test exists to check.
    #[tokio::test]
    async fn wire_index_hashes_are_what_the_serve_path_advertises_780() {
        use crate::federation::FederationDirectory as _;
        let backend = test_backend();
        // v62.0.0 (RL-fix2c) — a rooted serving node (the serve wait, CC 5.3.4).
        crate::federation::edition2::serve_wait_invariants::test_support::root_the_serving_node(
            &backend,
            "rl2c-backend-suite",
        )
        .await;
        for k in ["adv-a", "adv-b"] {
            put_e2_key(
                &backend,
                k,
                crate::federation::types::identity_type::PRIMITIVE,
            )
            .await;
        }
        let mut ids = Vec::new();
        for i in 0..7 {
            let id = format!("adv-{i}");
            let mut row = fix_attestation(&id, "adv-a", "adv-b", "adv-a");
            row.attestation_type = crate::federation::types::attestation_type::SCORES.into();
            resign_fix(&mut row);
            put_voiced(&backend, &row).await.expect("seed");
            // v62.0.0 (E5) — the stored id is the computed row id.
            ids.push(e2::rid(&row));
        }

        // Page the index with a deliberately small limit, so the cursor is
        // exercised rather than one page happening to cover everything.
        let mut paged: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = backend
                .list_wire_hashes_since("Attestation", cursor.as_deref(), 2)
                .await
                .expect("hash page");
            if page.is_empty() {
                break;
            }
            cursor = page.last().cloned();
            paged.extend(page);
        }
        assert_eq!(
            paged.len(),
            ids.len(),
            "#780: the paged walk must be COMPLETE — a dropped entry leaves a held row in the \
             consumer's `want` forever, which is the non-convergence this read exists to avoid"
        );

        // …and each hash is the one the serve path would advertise for that
        // row: the bare `Attestation`, never a `Served*` wrapper.
        let mut advertised: Vec<String> = Vec::new();
        for id in &ids {
            let row = backend.get_attestation(id).await.unwrap().expect("row");
            let bytes = serde_json::to_vec(&row).expect("serialize");
            advertised.push(crate::federation::wire_index::content_hash_of_bytes(&bytes));
        }
        advertised.sort();
        let mut paged_sorted = paged.clone();
        paged_sorted.sort();
        assert_eq!(
            paged_sorted, advertised,
            "#780: an index hash the serve path does not advertise leaves the row in `want` \
             forever. They align by construction — the index hashes the bare row so node-local \
             `admitted_at` stays out — and this is the assertion that keeps it true."
        );
    }

    /// v38.4.0 (CIRISPersist#768) — **the reaper honours the producer's
    /// stated shelf life, and CANNOT eat evidence.**
    ///
    /// Three arms, because the middle one is the whole reason this drives
    /// the per-row purge door instead of `DELETE ... WHERE expires_at <
    /// now`: an expired `scores` row is reaped, an expired `withdraws` is
    /// REFUSED by [`check_purge_admission`] (structural composer), and an
    /// unexpired row is untouched. A bulk statement would delete all three.
    #[tokio::test]
    async fn reaper_purges_expired_but_never_evidence_768() {
        use crate::federation::FederationDirectory as _;
        let backend = test_backend();
        let now = chrono::Utc::now();
        let past = now - chrono::Duration::hours(2);
        let future = now + chrono::Duration::hours(2);

        for k in ["reap-a", "reap-b"] {
            put_e2_key(
                &backend,
                k,
                crate::federation::types::identity_type::PRIMITIVE,
            )
            .await;
        }

        // Expired, re-derivable claim → reapable.
        let mut expired = fix_attestation("reap-expired", "reap-a", "reap-b", "reap-a");
        expired.attestation_type = crate::federation::types::attestation_type::SCORES.into();
        expired.expires_at = Some(past);
        resign_fix(&mut expired);
        // Not yet expired → not offered at all.
        let mut live = fix_attestation("reap-live", "reap-a", "reap-b", "reap-a");
        live.attestation_type = crate::federation::types::attestation_type::SCORES.into();
        live.expires_at = Some(future);
        resign_fix(&mut live);
        // Expired WITHDRAWAL → evidence; the door must refuse it.
        // v62.0.0 (E5) — an edition-2 withdrawal names a held target (here the
        // live row, by its computed id).
        let withdrawal_of = |label: &str, expires| {
            let mut w = fix_attestation(label, "reap-a", "reap-b", "reap-a");
            w.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.into();
            w.attestation_envelope["references_attestation_id"] = serde_json::json!(e2::rid(&live));
            w.expires_at = Some(expires);
            resign_fix(&mut w);
            w
        };
        let expired_withdraws = withdrawal_of("reap-withdraws", past);
        let (expired_id, withdraws_id, live_id) = (
            e2::rid(&expired),
            e2::rid(&expired_withdraws),
            e2::rid(&live),
        );

        for row in [&live, &expired, &expired_withdraws] {
            put_voiced(&backend, row).await.expect("seed");
        }

        // The sweep only ever offers rows past their stated expiry.
        let offered = backend
            .list_expired_attestation_ids(now, 100, 0)
            .await
            .expect("list expired");
        assert!(
            !offered.contains(&live_id),
            "#768: an UNEXPIRED row must never be offered to the reaper: {offered:?}"
        );

        let (purged, refused) = backend
            .reap_expired_attestations(now, 100)
            .await
            .expect("reap");
        assert_eq!(
            (purged, refused),
            (1, 0),
            "#768: one reapable claim purged. `refused` is 0 because the candidate query no \
             longer OFFERS structurally-refused types at all (PR #769 review round 2) — \
             paging past them bounded a short prefix only, and a long one still starved."
        );
        // ...and the DOOR still refuses it independently of what the query
        // chooses to offer. Asserted directly, because narrowing the query
        // would otherwise retire the only witness that the gate itself
        // discriminates — leaving the guard untested the day a future
        // candidate query widens again.
        assert!(
            crate::federation::FederationDirectory::purge_attestation_v31(&backend, &withdraws_id)
                .await
                .is_err(),
            "#768: the purge DOOR refuses a withdrawal on its own authority — the query \
             filter is an optimisation, not the guarantee"
        );
        assert!(
            backend
                .get_attestation(&expired_id)
                .await
                .unwrap()
                .is_none(),
            "#768: the expired claim is gone — its producer said when it stops speaking"
        );
        assert!(
            backend
                .get_attestation(&withdraws_id)
                .await
                .unwrap()
                .is_some(),
            "#768: an expired WITHDRAWS must survive — a retraction is a statement about \
             the past, and the purge door refuses it whatever this sweep believes. A bulk \
             DELETE on expires_at would have removed it silently."
        );
        assert!(
            backend.get_attestation(&live_id).await.unwrap().is_some(),
            "#768: an unexpired row is untouched"
        );

        // PR #769 review — **the sweep must not wedge behind refusals.**
        // A prefix of expired-but-unpurgeable rows (a withdrawal is refused
        // today and forever) previously re-offered itself every pass, so a
        // purgeable row behind it was never reached. Seed one more expired
        // withdrawal OLDER than a purgeable claim and require the claim to
        // still be reaped.
        let older = now - chrono::Duration::hours(9);
        let blocker = withdrawal_of("reap-blocker", older);
        let mut behind = fix_attestation("reap-behind", "reap-a", "reap-b", "reap-a");
        behind.attestation_type = crate::federation::types::attestation_type::SCORES.into();
        behind.expires_at = Some(older + chrono::Duration::minutes(1));
        resign_fix(&mut behind);
        let (blocker_id, behind_id) = (e2::rid(&blocker), e2::rid(&behind));
        for row in [blocker, behind] {
            put_voiced(&backend, &row).await.expect("seed blocked pair");
        }
        // A batch of ONE: the oldest expired row is the immovable withdrawal.
        let (p2, r2) = backend
            .reap_expired_attestations(now, 1)
            .await
            .expect("reap past the blocker");
        assert_eq!(
            (p2, r2),
            (1, 0),
            "#768: a batch of ONE must still reach the purgeable row even though an older \
             expired withdrawal sits ahead of it — otherwise a 95%-expired node makes no \
             progress. `refused` is 0 because the immovable row is no longer OFFERED; \
             paging alone bounded only a short prefix (PR #769 review round 2)"
        );
        assert!(
            backend.get_attestation(&behind_id).await.unwrap().is_none(),
            "#768: the row behind the immovable prefix was reaped"
        );
        assert!(
            backend
                .get_attestation(&blocker_id)
                .await
                .unwrap()
                .is_some(),
            "#768: and the withdrawal it paged past is still there"
        );

        // PR #769 review round 2 — **the projections go with the row.**
        // The node holds `consent_peer_set` and `signed_wire_index`, and the
        // reaper's first shape left both behind: an
        // expired grant purged while `list_consent_peers` still returned
        // the peer it authorised. Seed a projection row against a purgeable
        // attestation and require it gone.
        let mut granted = fix_attestation("reap-grant", "reap-a", "reap-b", "reap-a");
        granted.attestation_type = crate::federation::types::attestation_type::SCORES.into();
        granted.expires_at = Some(past);
        resign_fix(&mut granted);
        put_voiced(&backend, &granted).await.expect("seed granted");
        // v62.0.0 (E5) — keyed by the identity-refs and the computed row id.
        let granted_id = e2::rid(&granted);
        let (ka, kb) = (e2::kid("reap-a"), e2::kid("reap-b"));
        backend
            .test_execute(&format!(
                "INSERT OR REPLACE INTO consent_peer_set (node_key_id, for_key_id, peer_key_id, \
                    source_attestation_id, asserted_at) \
                 VALUES ('{ka}', '{ka}', '{kb}', '{granted_id}', '{}')",
                now.to_rfc3339()
            ))
            .await;
        let (p3, _) = backend
            .reap_expired_attestations(now, 10)
            .await
            .expect("reap grant");
        assert!(p3 >= 1, "#768: the expired grant is reaped");
        assert!(
            backend.test_query_i64(&format!(
                "SELECT COUNT(*) FROM consent_peer_set WHERE source_attestation_id = '{granted_id}'"
            )) == 0,
            "PR#769: the consent projection must die WITH the grant — otherwise the peer \
             stays authorised after the attestation authorising it is gone"
        );

        // Bound: max_rows=0 is a no-op, never a full sweep.
        assert_eq!(
            backend.reap_expired_attestations(now, 0).await.unwrap(),
            (0, 0),
            "#768: a zero batch reaps nothing"
        );
    }

    #[tokio::test]
    async fn trust_doors_refuse_the_unproven_721() {
        // v62.0.0 (JSON cut, E5) — the trust plane on edition 2 (T2.api §6): a
        // grant is the granter's `trust:accepts:v1` edge, projected into the
        // trust store (`trusted_by` = the edge's iss); a revocation is the
        // granter's `withdraws` of it. The earlier arms that tampered with a
        // JSON `SignedTrustGrant`'s signature, or re-signed it under another
        // key while naming the granter, are gone with that object: an
        // edition-2 edge is verified at the door (the key-of-issuer check,
        // `kid_not_of_iss`), and another key's edge is simply its own grant.
        use crate::federation::edition2::group_fixtures::row_id_of;
        use crate::federation::edition2::typed_fixtures as tf;
        use crate::federation::FederationDirectory as _;
        let backend = test_backend();
        for k in ["granter-721", "imposter-721", "subject-721"] {
            put_e2_key(&backend, k, crate::federation::types::identity_type::USER).await;
        }
        let (granter, imposter, subject) = (
            e2::kid("granter-721"),
            e2::kid("imposter-721"),
            e2::kid("subject-721"),
        );
        let at = e2::ms(chrono::Utc::now());

        // The granter's edge lands and projects.
        let edge = tf::trust_accepts_statement(&granter, &subject, &[], None, "federation", at);
        e2::put_statement(&backend, &edge)
            .await
            .expect("a proven grant admits");
        let row = backend.lookup_trust(&subject).await.unwrap().unwrap();
        assert_eq!(row.trusted_by, granter);

        // Only the granter withdraws its own grant.
        let edge_id = row_id_of(&edge);
        // E5-fix1 (round 3) — refused or HELD (the granter is read from the
        // held edge, another row: CC 2.7.3); either way it does not land.
        NotLanded::of(
            &backend,
            e2::put_statement(
                &backend,
                &tf::trust_withdraws_statement(&imposter, &subject, &edge_id, at + 1),
            )
            .await,
            "a non-granter's withdraws of the edge must refuse",
        )
        .await;
        assert!(
            backend.lookup_trust(&subject).await.unwrap().is_some(),
            "no refused withdraws may half-land"
        );
        let withdraw = tf::trust_withdraws_statement(&granter, &subject, &edge_id, at + 2);
        e2::put_statement(&backend, &withdraw)
            .await
            .expect("the granter's withdraws lands");
        // Idempotent second withdraws: the same row, held.
        e2::put_statement(&backend, &withdraw)
            .await
            .expect("re-offering the withdraws is a no-op");
    }

    // ─── v31.4.0 (CIRISPersist#682 / #668) — identity-plane fixtures ──

    // ── #236 CC 4.4.3.4.3 / CC 3.4.7.3 — reject-agency-on-node-key gate ───

    /// v30.8.0 (CIRISConstitution#87) — a delegation carrying the CC 2.4.1.2
    /// **owner-binding marker**: an explicit claim of custody over the target.
    ///
    /// The steward-gate tests need this now. Before the ruling, an UNMARKED
    /// `delegates_to(user → user)` was itself read as a steward binding, so those
    /// tests could assert CC 3.2's refusals against a bare edge. CC 3.2 rc3 ruled
    /// that unmarked edge is a capability CONFERRAL — giving a person a job — and
    /// it is now admitted. Testing the custody rule therefore requires stating
    /// custody, which is what this helper does.
    ///
    /// The refusals those tests assert are unchanged; only the shape that
    /// triggers them is now explicit.
    fn fix_owner_binding_delegates_to(
        id: &str,
        attesting: &str,
        attested: &str,
        scrub_key_id: &str,
        scope: &[&str],
    ) -> Attestation {
        let mut att = fix_attestation(id, attesting, attested, scrub_key_id);
        att.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
        crate::federation::tier_ingest::test_support::reseal(&mut att);
        att.attestation_envelope = serde_json::json!({
            "id": id,
            "scope": scope.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            "delegation_purpose": crate::federation::types::owner_binding::CC_DELEGATION_PURPOSE,
        });
        resign_fix(&mut att); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        att
    }

    /// v0.3.6 (CIRISPersist#15) — Helper: insert a trace_events row
    /// scoped to (agent_id_hash, signing_key_id). Returns the
    /// trace_id used so the caller can pair an LLM call.
    fn dsar_fixture_row(
        agent_id_hash: &str,
        signing_key_id: &str,
        trace_suffix: &str,
    ) -> TraceEventRow {
        TraceEventRow {
            trace_id: format!("trace-{trace_suffix}"),
            thought_id: format!("th-{trace_suffix}"),
            task_id: None,
            step_point: None,
            event_type: ReasoningEventType::ThoughtStart,
            attempt_index: 0,
            ts: "2026-04-30T00:00:00Z".parse().unwrap(),
            agent_name: None,
            agent_id_hash: agent_id_hash.to_owned(),
            cognitive_state: None,
            trace_level: TraceLevel::Generic,
            payload: serde_json::Map::new(),
            cost_llm_calls: None,
            cost_tokens: None,
            cost_usd: None,
            signature: "AAAA".into(),
            signing_key_id: signing_key_id.to_owned(),
            signature_verified: true,
            verification_source: crate::store::VerificationSource::Persist,
            schema_version: "2.7.0".into(),
            pii_scrubbed: false,
            original_content_hash: None,
            scrub_signature: None,
            scrub_key_id: None,
            scrub_timestamp: None,
            // v32.0.0 (#690) — no scrub ran here, so no claim is made.
            // v32.1.0 (#606) — the backend stamps this at insert.
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

    /// v0.3.6 (CIRISPersist#15) — Per-key DSAR scope: deletion is
    /// scoped to (agent_id_hash, signing_key_id). Traces signed under
    /// other keys for the same agent stay alive — the per-key
    /// authorization model means the DSAR can only delete what its
    /// signing key signed.
    #[tokio::test]
    async fn dsar_per_key_scopes_correctly() {
        use crate::store::Backend;
        let backend = test_backend();
        // v57.0.0 (#988 item 2) — a hard_case row needs this node's key.
        crate::federation::hard_case::test_support::declare_node(&backend, "suite-test-node").await;
        // Same agent_id_hash, two different signing keys (key1 + key2).
        // Plus a different agent's row (other) under the same key1.
        backend
            .insert_trace_events_batch(&[
                dsar_fixture_row("agent-A", "key1", "k1-t1"),
                dsar_fixture_row("agent-A", "key1", "k1-t2"),
                dsar_fixture_row("agent-A", "key2", "k2-t1"),
                dsar_fixture_row("agent-B", "key1", "B-t1"),
            ])
            .await
            .unwrap();

        // DSAR for (agent-A, key1) — deletes only the 2 key1 rows.
        let summary = backend
            .delete_traces_for_agent("agent-A", "key1", false)
            .await
            .unwrap();
        assert_eq!(summary.trace_events_deleted, 2);
        assert_eq!(summary.federation_keys_deleted, 0);

        // Surviving rows: agent-A's key2 row + agent-B's key1 row.
        let remaining = backend.snapshot_events();
        assert_eq!(remaining.len(), 2);
        assert!(remaining
            .iter()
            .any(|r| r.agent_id_hash == "agent-A" && r.signing_key_id == "key2"));
        assert!(remaining
            .iter()
            .any(|r| r.agent_id_hash == "agent-B" && r.signing_key_id == "key1"));

        // Idempotent: re-invocation on the now-deleted scope returns 0.
        let summary2 = backend
            .delete_traces_for_agent("agent-A", "key1", false)
            .await
            .unwrap();
        assert_eq!(summary2.trace_events_deleted, 0);
    }

    /// v0.3.6 (CIRISPersist#15) — Per-key cascade through trace_llm_calls.
    /// LLM call rows joined by trace_id only cascade for the targeted
    /// key's traces. Cross-key LLM calls survive.
    #[tokio::test]
    async fn dsar_per_key_cascades_llm_calls() {
        use crate::store::Backend;
        let backend = test_backend();
        // v57.0.0 (#988 item 2) — a hard_case row needs this node's key.
        crate::federation::hard_case::test_support::declare_node(&backend, "suite-test-node").await;
        backend
            .insert_trace_events_batch(&[
                dsar_fixture_row("agent-A", "key1", "k1-t1"),
                dsar_fixture_row("agent-A", "key2", "k2-t1"),
            ])
            .await
            .unwrap();
        // One LLM call per trace.
        for trace_id in ["trace-k1-t1", "trace-k2-t1"] {
            backend
                .insert_trace_llm_calls_batch(&[TraceLlmCallRow {
                    trace_id: trace_id.into(),
                    thought_id: "th".into(),
                    task_id: None,
                    parent_event_id: None,
                    parent_event_type: ReasoningEventType::ThoughtStart,
                    parent_attempt_index: 0,
                    attempt_index: 0,
                    ts: "2026-04-30T00:00:00Z".parse().unwrap(),
                    duration_ms: 0.0,
                    handler_name: "h".into(),
                    service_name: "s".into(),
                    model: None,
                    base_url: None,
                    response_model: None,
                    prompt_tokens: None,
                    completion_tokens: None,
                    prompt_bytes: None,
                    completion_bytes: None,
                    cost_usd: None,
                    status: crate::schema::LlmCallStatus::Ok,
                    error_class: None,
                    attempt_count: None,
                    retry_count: None,
                    prompt_hash: None,
                    prompt: None,
                    response_text: None,
                }])
                .await
                .unwrap();
        }

        // DSAR for (agent-A, key1) — cascades only the key1 LLM call.
        let summary = backend
            .delete_traces_for_agent("agent-A", "key1", false)
            .await
            .unwrap();
        assert_eq!(summary.trace_events_deleted, 1);
        assert_eq!(summary.trace_llm_calls_deleted, 1);

        // The key2 LLM call survives.
        let remaining = backend.snapshot_llm_calls();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].trace_id, "trace-k2-t1");
    }

    /// v7.0.0 (CIRISPersist#222) — full Art. 17 erasure deletes the
    /// agent's traces across ALL signing keys (contrast the per-key
    /// `delete_traces_for_agent`), cascades LLM calls by trace_id,
    /// emits a `hard_case:trace_erasure` audit row, and is idempotent.
    #[tokio::test]
    async fn erasure_deletes_all_keys_cascades_and_audits() {
        use crate::federation::{hard_case, FederationDirectory, HardCaseFilter};
        use crate::store::Backend;
        let backend = test_backend();
        // v57.0.0 (#988 item 2) — a hard_case row needs this node's key.
        crate::federation::hard_case::test_support::declare_node(&backend, "suite-test-node").await;
        // agent-A under two keys + an unrelated agent-B.
        backend
            .insert_trace_events_batch(&[
                dsar_fixture_row("agent-A", "key1", "A-k1"),
                dsar_fixture_row("agent-A", "key2", "A-k2"),
                dsar_fixture_row("agent-B", "key1", "B-k1"),
            ])
            .await
            .unwrap();
        for trace_id in ["trace-A-k1", "trace-A-k2", "trace-B-k1"] {
            backend
                .insert_trace_llm_calls_batch(&[TraceLlmCallRow {
                    trace_id: trace_id.into(),
                    thought_id: "th".into(),
                    task_id: None,
                    parent_event_id: None,
                    parent_event_type: ReasoningEventType::ThoughtStart,
                    parent_attempt_index: 0,
                    attempt_index: 0,
                    ts: "2026-04-30T00:00:00Z".parse().unwrap(),
                    duration_ms: 0.0,
                    handler_name: "h".into(),
                    service_name: "s".into(),
                    model: None,
                    base_url: None,
                    response_model: None,
                    prompt_tokens: None,
                    completion_tokens: None,
                    prompt_bytes: None,
                    completion_bytes: None,
                    cost_usd: None,
                    status: crate::schema::LlmCallStatus::Ok,
                    error_class: None,
                    attempt_count: None,
                    retry_count: None,
                    prompt_hash: None,
                    prompt: None,
                    response_text: None,
                }])
                .await
                .unwrap();
        }

        // Erase agent-A: both keys' traces (2) + their 2 LLM calls.
        let summary = backend
            .delete_traces_for_agent_id_hash("agent-A")
            .await
            .unwrap();
        assert_eq!(summary.trace_events, 2, "both keys' traces");
        assert_eq!(summary.trace_llm_calls, 2);
        // No detection rows were seeded — nothing to tombstone.
        assert_eq!(summary.detection_events_tombstoned, 0);

        // agent-B survives untouched.
        let remaining = backend.snapshot_events();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].agent_id_hash, "agent-B");
        assert_eq!(backend.snapshot_llm_calls().len(), 1);

        // Audit: exactly one hard_case:trace_erasure row for agent-A.
        let events = backend
            .list_hard_case_events(HardCaseFilter {
                kind: Some(hard_case::kind::TRACE_ERASURE.into()),
                since: None,
                emitter_key_id: None,
            })
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        // v58.0.0 (CIRISPersist#1094 item 2, CC 4.5.3) — the row names nobody.
        assert_eq!(events[0].target_key_id, None);
        assert!(!events[0].detail.to_string().contains("agent-A"));
        assert_eq!(events[0].detail["trace_events"], 2);
        assert_eq!(events[0].detail["trace_llm_calls"], 2);

        // Idempotent: a second erasure returns all-zero and emits NO
        // new audit row (clean no-op).
        let summary2 = backend
            .delete_traces_for_agent_id_hash("agent-A")
            .await
            .unwrap();
        assert_eq!(summary2.trace_events, 0);
        assert_eq!(summary2.trace_llm_calls, 0);
        let events2 = backend
            .list_hard_case_events(HardCaseFilter {
                kind: Some(hard_case::kind::TRACE_ERASURE.into()),
                since: None,
                emitter_key_id: None,
            })
            .await
            .unwrap();
        assert_eq!(events2.len(), 1, "idempotent re-run emits no new audit");
    }

    /// v0.3.5 (CIRISLens#8 ASK 3) — fetch_trace_events_page returns
    /// rows in event_id order, respects the cursor, respects the limit.
    #[tokio::test]
    async fn fetch_trace_events_page_cursors_correctly() {
        use crate::store::Backend;
        let backend = test_backend();
        for i in 0..5 {
            let row = TraceEventRow {
                trace_id: format!("trace-{i}"),
                thought_id: format!("th-{i}"),
                task_id: None,
                step_point: None,
                event_type: ReasoningEventType::ThoughtStart,
                attempt_index: 0,
                ts: "2026-04-30T00:00:00Z".parse().unwrap(),
                agent_name: None,
                agent_id_hash: format!("agent-{}", i % 2),
                cognitive_state: None,
                trace_level: TraceLevel::Generic,
                payload: serde_json::Map::new(),
                cost_llm_calls: None,
                cost_tokens: None,
                cost_usd: None,
                signature: "AAAA".into(),
                signing_key_id: "k".into(),
                signature_verified: true,
                verification_source: crate::store::VerificationSource::Persist,
                schema_version: "2.7.0".into(),
                pii_scrubbed: false,
                original_content_hash: None,
                scrub_signature: None,
                scrub_key_id: None,
                scrub_timestamp: None,
                // v32.0.0 (#690) — no scrub ran here, so no claim is made.
                // v32.1.0 (#606) — the backend stamps this at insert.
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
            };
            backend.insert_trace_events_batch(&[row]).await.unwrap();
        }
        // Page 1: limit=2 returns first 2 by event_id.
        let page1 = backend.fetch_trace_events_page(0, 2, None).await.unwrap();
        assert_eq!(page1.len(), 2);
        let last_eid = page1.last().unwrap().0;
        // Page 2: cursor = last from page 1.
        let page2 = backend
            .fetch_trace_events_page(last_eid, 2, None)
            .await
            .unwrap();
        assert_eq!(page2.len(), 2);
        assert!(page2.iter().all(|(eid, _)| *eid > last_eid));
        // Filtered by agent_id_hash.
        let filtered = backend
            .fetch_trace_events_page(0, 100, Some("agent-0"))
            .await
            .unwrap();
        assert!(filtered
            .iter()
            .all(|(_, row)| row.agent_id_hash == "agent-0"));
    }

    /// Build a `withdraws` against `target_id` (CIRISPersist#146 Ask 2).
    fn fix_withdraws(id: &str, issuer: &str, target_id: &str) -> Attestation {
        let mut w = fix_attestation(id, issuer, issuer, issuer);
        w.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.into();
        w.attestation_envelope = serde_json::json!({
            "references_attestation_id": target_id,
            "withdrawal_reason": "test",
        });
        resign_fix(&mut w); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        w
    }

    fn fix_delegates_to(
        id: &str,
        granter: &str,
        grantee: &str,
        scope: serde_json::Value,
    ) -> Attestation {
        let mut d = fix_attestation(id, granter, grantee, granter);
        d.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
        // v62.0.0 (E5) — the earlier form echoed the row's own chosen id as
        // `references_attestation_id`; an edition-2 row cannot name its own
        // (computed) id, so the label rides as the `id` member.
        d.attestation_envelope = if e2::emit_edition2() {
            serde_json::json!({ "id": id, "scope": scope })
        } else {
            // The earlier form (held tests) keeps its self-reference.
            serde_json::json!({ "references_attestation_id": id, "scope": scope })
        };
        resign_fix(&mut d); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        d
    }

    /// v62.0.0 (CW-fix1 fixture fix, 4u) — [`fix_delegates_to`] for a ROOM
    /// duty: the edge NAMES its room (`community_id`, keyed as
    /// `fix_scores_report` keys it), the only edge a room's duty walk follows.
    fn fix_delegates_to_in(
        id: &str,
        granter: &str,
        grantee: &str,
        scope: serde_json::Value,
        community: &str,
    ) -> Attestation {
        let mut d = fix_delegates_to(id, granter, grantee, scope);
        d.attestation_envelope["community_id"] =
            serde_json::Value::String(if e2::emit_edition2() {
                e2::kid_or_keep(community)
            } else {
                community.to_owned()
            });
        resign_fix(&mut d);
        d
    }

    /// #973 — a node's acceptance edge toward a root, naming its job
    /// (`trust:accepts:v1`). An unlabelled `delegates_to` gives no acceptance.
    fn fix_accepts(id: &str, node: &str, root: &str, scope: serde_json::Value) -> Attestation {
        let mut d = fix_delegates_to(id, node, root, scope);
        d.attestation_envelope["dimension"] =
            serde_json::json!(crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION);
        resign_fix(&mut d);
        d
    }

    /// v18.2.0 (CIRISPersist#481) — the pluggable-trust-root witnesses
    /// through the REAL write + walk surfaces:
    /// 1. self-root `attestation(user → user)` ADMITS;
    /// 2. a root that charters itself (`trust:charter:v1`) and a user's own
    ///    `trust:accepts` edge to it;
    /// 3. `trust_root_valid` evaluates the predicate (edge + self-declaration
    ///    + recovery + holders; the drill and halt latch are reported only);
    /// 4. the user's `withdraws` of its edge makes the walk treat it as ABSENT
    ///    (nuclear un-trust; base self-root untouched).
    ///
    /// E5-fix2 (round 6; CP2) — PORTED to an edition-2 root (E9's twins): a
    /// key-arm root hand-chartered by a fixture key is never valid under
    /// edition 2 (its holder's custody evidence, CC 4.2.2.1). The "(3) fresh
    /// drill reads Green" leg is not carried: no edition-2 producer states an
    /// accord heartbeat about a fixture root (its signer needs accord
    /// standing); the drill's band is #551's witness below and the edition-2
    /// "undrilled ⇒ Red, still valid" is `operational`'s ceremony walk.
    ///
    /// v62.0.0 (R2-fixture; CC 3.2 T5) — the root is the bundle's LINEAGE
    /// (`fixture_genesis::install_v2`): "the root charters itself" is the
    /// bundle's `charter` member, and the user's edge is its acceptance of the
    /// lineage (`accept_lineage_e2`).
    #[tokio::test]
    async fn trust_root_walk_and_tombstone_481() {
        use crate::federation::operational::test_support::{accept_lineage_e2, withdraw_e2};
        use crate::federation::trust_root::{trust_root_valid, TrustRootVerdict};
        let backend = test_backend();
        let user = put_e2_key(&backend, "tr-user", "user").await;

        // Ask 1 — the self-root base admits (attesting == attested == self).
        put_voiced(
            &backend,
            &fix_attestation("tr-self", "tr-user", "tr-user", "tr-user"),
        )
        .await
        .expect("(1) self-root attestation(user→user) must admit");

        // Ask 2 — the bundle in force (its charter); the user's own edge.
        crate::federation::edition2::fixture_genesis::install_v2(&backend)
            .await
            .expect("(2) the bundle in force");
        let root = crate::federation::edition2::fixture_genesis::FAMILY_KEY_ID;
        let edge = accept_lineage_e2(&backend, "tr-user")
            .await
            .expect("the user's trust edge must admit");

        // Ask 3 — the walk: every hard leg green.
        let v: TrustRootVerdict =
            trust_root_valid(&backend, &user, root, crate::host::clock::now())
                .await
                .expect("walk");
        assert!(v.edge_exists, "(3) live user→root edge: {v:?}");
        assert!(v.root_self_declares, "(3) root self-declares: {v:?}");
        assert_ne!(v.halt_latched, Some(true), "(3) no halt latched");
        assert!(v.valid, "(3) all legs ⇒ valid: {v:?}");

        // A self-root is the immutable BASE, never a valid EXTERNAL root.
        let v0 = trust_root_valid(&backend, &user, &user, crate::host::clock::now())
            .await
            .expect("walk self");
        assert!(
            !v0.valid && !v0.edge_exists,
            "base self-root ≠ external root"
        );

        // Ask 4 — nuclear un-trust: withdraw the edge; the walk folds it
        // ABSENT. The root's own declaration stands.
        withdraw_e2(&backend, "tr-user", root, &edge)
            .await
            .expect("(4) withdraws on own edge must admit");
        let v2 = trust_root_valid(&backend, &user, root, crate::host::clock::now())
            .await
            .expect("walk post-tombstone");
        assert!(!v2.edge_exists, "(4) tombstoned edge is ABSENT to the walk");
        assert!(!v2.valid, "(4) un-trust revokes validity");
        assert!(
            v2.root_self_declares,
            "(4) only the EDGE died — the root's own declaration stands"
        );
    }

    /// v23.0.0 (CIRISPersist#551 item 4) — **the drill is a trust SIGNAL, not
    /// a functionality gate.** `valid` never consults the drill; an undrilled
    /// root still serves, and says so (`Red`, `last_drill_at: None`). The hard
    /// gates are untouched: the user's un-trust still collapses validity.
    ///
    /// E5-fix2 (round 6; CP2) — PORTED to edition-2 roots (E9's twins). The
    /// Green / Yellow band legs are not carried: they need a heartbeat about
    /// the root from a signer with accord standing, which no edition-2 fixture
    /// produces for a fixture root (the banding itself is the private
    /// `DrillFreshness::of`).
    ///
    /// v62.0.0 (R2-fixture; CC 3.2 T5) — the root is the bundle's lineage.
    #[tokio::test]
    async fn drill_freshness_is_a_signal_not_a_gate_551() {
        use crate::federation::operational::test_support::{accept_lineage_e2, withdraw_e2};
        use crate::federation::trust_root::{trust_root_valid, DrillFreshness};
        let backend = test_backend();
        let user = put_e2_key(&backend, "drill-user", "user").await;
        crate::federation::edition2::fixture_genesis::install_v2(&backend)
            .await
            .expect("the bundle in force");
        let root = crate::federation::edition2::fixture_genesis::FAMILY_KEY_ID;
        let edge = accept_lineage_e2(&backend, "drill-user")
            .await
            .expect("the user's edge");

        // Never drilled: valid, and RED.
        let never = trust_root_valid(&backend, &user, root, crate::host::clock::now())
            .await
            .unwrap();
        assert!(
            never.valid,
            "an undrilled root still serves — governance signal, not a gate: {never:?}"
        );
        assert_eq!(never.drill_freshness, DrillFreshness::Red, "{never:?}");
        assert_eq!(never.last_drill_at, None, "never drilled, and it says so");

        // The HARD gate still works: the user un-trusts → invalid.
        withdraw_e2(&backend, "drill-user", root, &edge)
            .await
            .expect("the user withdraws its edge");
        let unrooted = trust_root_valid(&backend, &user, root, crate::host::clock::now())
            .await
            .unwrap();
        assert!(
            !unrooted.valid,
            "un-trust still collapses validity: {unrooted:?}"
        );
        assert_eq!(
            unrooted.drill_freshness,
            DrillFreshness::Red,
            "…and the drill signal is reported independently of the gate"
        );
    }

    /// v21.0.0 (CIRISPersist#502 E5) — a LOCAL-tier delegates_to/charter
    /// must NEVER count in the capability walk. Before this a local-tier
    /// `delegates_to(user→root)` + local-tier root self-charter silently
    /// satisfied `trust_root_valid` (the hole under all 95 claim families).
    #[tokio::test]
    async fn local_tier_rows_do_not_count_in_capability_walk_502e5() {
        use crate::federation::trust_root::trust_root_valid;
        let backend = test_backend();
        for (k, it) in [
            ("e5-user", "user"),
            ("e5-root", "node"),
            ("e5-la", "accord_holder"),
        ] {
            // v62.0.0 (E5) — an edition-2 `key:record` (hardware evidence is not
            // carried by the fixture record).
            put_e2_key(&backend, k, it).await;
        }
        // Build the full valid-root fixture but flip every capability row to
        // LOCAL tier — the walk must treat them as absent.
        let mut charter = fix_charter(
            "e5-c",
            "e5-root",
            serde_json::json!(["infra:serve", "infra:attest"]),
        );
        charter.tier = crate::federation::types::attestation_tier::LOCAL.to_string();
        resign_fix(&mut charter);
        put_voiced(&backend, &charter).await.unwrap();

        let mut edge = fix_delegates_to(
            "e5-e",
            "e5-user",
            "e5-root",
            serde_json::json!(["infra:serve"]),
        );
        edge.tier = crate::federation::types::attestation_tier::LOCAL.to_string();
        resign_fix(&mut edge);
        put_voiced(&backend, &edge).await.unwrap();

        let mut lc = fix_attestation("e5-lc", "e5-la", "e5-root", "e5-la");
        lc.attestation_envelope = serde_json::json!({
            "id": "e5-lc", "dimension": "accord:lifecycle:v1", "score": 1.0, "confidence": 0.9,
        });
        lc.asserted_at = chrono::Utc::now();
        lc.tier = crate::federation::types::attestation_tier::LOCAL.to_string();
        resign_fix(&mut lc);
        put_voiced(&backend, &lc).await.unwrap();

        let v = trust_root_valid(
            &backend,
            &e2::kid("e5-user"),
            &e2::kid("e5-root"),
            crate::host::clock::now(),
        )
        .await
        .unwrap();
        assert!(!v.edge_exists, "local-tier edge must not count");
        assert!(!v.root_self_declares, "local-tier charter must not count");
        assert_eq!(
            v.last_drill_at, None,
            "a local-tier drill row must not register as a drill"
        );
        assert!(!v.valid, "no local-tier row satisfies the capability gate");
    }

    /// v19.0.0 (CIRISPersist#488) — the RC3 charter deltas, all three:
    /// (1) CRITICAL: a charter without a pre-rotation commitment REFUSES at
    /// admission; a recovery declaration must BIND to the predecessor's
    /// pre-committed successor set; (2) serve∧attest AND-minimum — a
    /// serve-only self-loop is not a root (v62.0.0 R2-valid: no key is); (3)
    /// an EXPIRED trust edge is as dead to the walk as a tombstoned one.
    #[tokio::test]
    async fn rc3_charter_deltas_488() {
        use crate::federation::trust_root::{test_pre_rotation_commitment, trust_root_valid};
        let backend = test_backend();
        for (k, it) in [
            ("rc-user", "user"),
            ("rc-root", "node"),
            ("rc-root2", "node"),
        ] {
            // v62.0.0 (E5) — an edition-2 `key:record` (hardware evidence is not
            // carried by the fixture record).
            put_e2_key(&backend, k, it).await;
        }

        // (1) commitment-less charter REFUSES with the typed kind.
        let err = NotLanded::of(
            &backend,
            put_voiced(&backend, &{
                // E5-fix2 (round 6) — a CHARTER names its job (#973: an
                // unlabelled self-loop is no charter, so the charter gate never
                // reads it): `trust:charter:v1`, with the commitment removed.
                let mut bare = fix_charter(
                    "rc-bare",
                    "rc-root",
                    serde_json::json!(["infra:serve", "infra:attest"]),
                );
                if let Some(o) = bare.attestation_envelope.as_object_mut() {
                    o.remove("pre_rotation_commitment");
                }
                resign_fix(&mut bare);
                bare
            })
            .await,
            "(1) charter without pre-rotation commitment must refuse",
        )
        .await;
        assert_eq!(err.kind(), "federation_charter_invalid", "{err:?}");

        // (2) serve-only charter admits (it is a valid delegates_to) but is
        // NOT a root to the walk — the AND-minimum.
        put_voiced(
            &backend,
            &fix_charter(
                "rc-serveonly",
                "rc-root2",
                serde_json::json!(["infra:serve"]),
            ),
        )
        .await
        .expect("serve-only self-loop admits (charter-shaped, commitment present)");
        put_voiced(
            &backend,
            &fix_accepts(
                "rc-edge2",
                "rc-user",
                "rc-root2",
                serde_json::json!(["infra:serve"]),
            ),
        )
        .await
        .unwrap();
        let v = trust_root_valid(
            &backend,
            &e2::kid("rc-user"),
            &e2::kid("rc-root2"),
            crate::host::clock::now(),
        )
        .await
        .unwrap();
        // v62.0.0 (R2-valid; CC 3.2 T5) — a key is no root whatever its
        // self-loop carries (the serve∧attest minimum was the KEYED root's):
        // not valid, by name.
        assert!(
            !v.root_self_declares && !v.valid && v.not_rooted.is_some(),
            "(2) a serve-only self-loop at a key is NOT a root: {v:?}"
        );

        // (3) an expired edge is dead to the walk. v62.0.0 (R2-valid) — the
        // edge is the user's acceptance of the bundle's LINEAGE, its
        // `valid_until` passed.
        crate::federation::operational::test_support::ensure_e2_genesis(&backend)
            .await
            .expect("(3) the bundle in force");
        let now = crate::host::clock::now();
        crate::federation::operational::test_support::accept_lineage_e2_at(
            &backend,
            "rc-user",
            e2::ms(now - chrono::Duration::minutes(10)),
            Some(e2::ms(now - chrono::Duration::minutes(5))),
        )
        .await
        .expect("(3) the expired acceptance is stored");
        let v3 = trust_root_valid(
            &backend,
            &e2::kid("rc-user"),
            crate::federation::edition2::fixture_genesis::FAMILY_KEY_ID,
            crate::host::clock::now(),
        )
        .await
        .unwrap();
        assert!(
            !v3.edge_exists && !v3.valid && v3.root_self_declares,
            "(3) an expired acceptance is ABSENT to the walk: {v3:?}"
        );

        // (1b) recovery binding: predecessor charter pre-commits to a
        // successor set; the bound successor charter ADMITS; a non-binding
        // one REFUSES; a non-member attester REFUSES.
        // v62.0.0 (E5) — successor keys are identity-refs (the keys' ids).
        let successors = vec![e2::kid("rc-root2"), e2::kid("rc-user")];
        let commitment = test_pre_rotation_commitment(&successors).unwrap();
        let mut pred = fix_delegates_to(
            "rc-pred",
            "rc-root",
            "rc-root",
            serde_json::json!(["infra:serve", "infra:attest"]),
        );
        pred.attestation_envelope = serde_json::json!({
            "id": "rc-pred",
            "scope": ["infra:serve", "infra:attest"],
            "pre_rotation_commitment": commitment,
        });
        resign_fix(&mut pred);
        put_voiced(&backend, &pred)
            .await
            .expect("predecessor charter admits");

        // Bound successor charter: attester rc-root2 ∈ pre-committed set.
        let mut succ = fix_charter(
            "rc-succ",
            "rc-root2",
            serde_json::json!(["infra:serve", "infra:attest"]),
        );
        let succ_env = serde_json::json!({
            "id": "rc-succ",
            "scope": ["infra:serve", "infra:attest"],
            "pre_rotation_commitment":
                test_pre_rotation_commitment(&["rc-next-a".to_owned()]).unwrap(),
            "recovers": e2::kid("rc-root"),
            "successor_keys": successors,
        });
        succ.attestation_envelope = succ_env;
        resign_fix(&mut succ);
        put_voiced(&backend, &succ)
            .await
            .expect("(1b) BOUND recovery charter admits");

        // Non-binding successor set → refused.
        let mut bad = succ.clone();
        bad.attestation_envelope["successor_keys"] =
            serde_json::json!([e2::kid("rc-root2"), "not-precommitted"]);
        resign_fix(&mut bad);
        let err = NotLanded::of(
            &backend,
            put_voiced(&backend, &bad).await,
            "(1b) non-binding successor set must refuse",
        )
        .await;
        assert_eq!(err.kind(), "federation_charter_invalid");
    }

    /// v18.3.0 (CIRISPersist#483) — the composed capability walk: a
    /// subject's `infra:serve`, granted by a root the asking user trusts,
    /// resolves to that root; when the user un-trusts the root (edge
    /// tombstone), the SAME subject grant no longer roots → `None`. This is
    /// edge#386's trace-serve gate: serve only under a COMMON valid root.
    #[tokio::test]
    async fn capability_roots_to_trusted_root_483() {
        // v62.0.0 (R2-fixture; CC 3.2 T5) — the root is the bundle's LINEAGE
        // (`fixture_trust_root::rooted_trust_root`, with this node's own
        // acceptance); the USER's own `trust:accepts` edge is its acceptance of
        // the lineage (`accept_lineage_e2`); the root's grant to the peer is
        // COUNTED over the bundle's holders (`put_conferral`, with the peer's
        // acceptance); the user un-trusts with its own `withdraws`. The peer is
        // a `user` key: a machine grantee's grant also waits on its bound
        // owner's voice (CC 4.4.3.19), which is not this witness's question.
        use crate::federation::operational::test_support::{accept_lineage_e2, withdraw_e2};
        use crate::federation::trust_root::{capability_roots_to_trusted_root, trust_root_valid};
        let backend = test_backend();
        backend.set_node_key_id(put_e2_key(&backend, "cr-node", "node").await);
        let user = put_e2_key(&backend, "cr-user", "user").await;
        let peer = put_e2_key(&backend, "cr-peer", "user").await;
        let r = e2::rooted_trust_root(
            &backend,
            &crate::federation::edition2::fixture_genesis::HOLDER_SEEDS,
            "quorum:2/3",
        )
        .await;
        let edge = accept_lineage_e2(&backend, "cr-user")
            .await
            .expect("the user accepts the root");
        assert!(
            trust_root_valid(&backend, &user, &r.lineage, crate::host::clock::now())
                .await
                .unwrap()
                .valid,
            "fixture: root is valid for the user"
        );

        // The root grants the PEER infra:serve.
        let granted = crate::federation::edition2::fixture_trust_root::put_conferral(
            &backend,
            &r,
            "cr-peer",
            &["infra:serve"],
        )
        .await
        .expect("the root confers on the peer");

        // #483 — the peer's infra:serve roots to a root the user trusts.
        let grant = capability_roots_to_trusted_root(
            &backend,
            &user,
            &peer,
            "infra:serve",
            crate::host::clock::now(),
        )
        .await
        .expect("walk")
        .expect("peer serves under a root the user trusts");
        assert_eq!(grant.root_key_id, r.lineage);
        assert_eq!(grant.grant_attestation_id, granted.hex());
        assert!(grant.verdict.valid);

        // A scope the peer was NOT granted → None.
        assert!(
            capability_roots_to_trusted_root(
                &backend,
                &user,
                &peer,
                "infra:store",
                crate::host::clock::now()
            )
            .await
            .unwrap()
            .is_none(),
            "ungranted scope roots nowhere"
        );

        // Un-trust the root: the peer's grant now roots to nothing.
        withdraw_e2(&backend, "cr-user", &r.lineage, &edge)
            .await
            .expect("the user withdraws its edge");
        assert!(
            capability_roots_to_trusted_root(
                &backend,
                &user,
                &peer,
                "infra:serve",
                crate::host::clock::now()
            )
            .await
            .unwrap()
            .is_none(),
            "un-trusting the root stops the peer serving immediately (edge#386)"
        );
    }

    /// Build a root CHARTER: self-loop `delegates_to(root → root)` carrying
    /// `scope` + the v19.0.0 (#488) pre-rotation commitment (over a
    /// deterministic test successor set) the charter admission gate requires.
    fn fix_charter(id: &str, root: &str, scope: serde_json::Value) -> Attestation {
        let successors = vec![format!("{root}-succ-a"), format!("{root}-succ-b")];
        let commitment =
            crate::federation::trust_root::test_pre_rotation_commitment(&successors).unwrap();
        let mut d = fix_attestation(id, root, root, root);
        d.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
        crate::federation::tier_ingest::test_support::reseal(&mut d);
        // v62.0.0 (E5) — no self-reference (see `fix_delegates_to`).
        d.attestation_envelope = serde_json::json!({
            "id": id,
            "scope": scope,
            "pre_rotation_commitment": commitment,
            // #973 — a charter names its job; an unlabelled one is no charter.
            "dimension": crate::federation::trust_root::TRUST_CHARTER_DIMENSION,
        });
        if !e2::emit_edition2() {
            // The earlier form (held tests) keeps its self-reference.
            d.attestation_envelope["references_attestation_id"] = serde_json::json!(id);
        }
        resign_fix(&mut d);
        d
    }

    // ── v8.7.1 (CIRISPersist#233, CEG RC24/RC25/RC26 §11.10/§11.11/
    // §5.6.8.10) — FULL §11.10 moderation enforcement on the report→
    // `scores` path (review / moderation dimensions). Replaces the v8.7.0
    // on_behalf_of model. Exercises the full matrix: (a) as-self subject,
    // (b1) subject-delegated chain, (b2) named-moderator, (c) no authority,
    // (c2) nothing → REJECT (the bypass-closed guard), (d) scope isolation,
    // (e) depth>5, (f) ⊆-parent attenuation violation, (g) deputization
    // without sub_delegation, (h) withdraws on mid-chain edge, (i)
    // non-steward-bound root.

    thread_local! {
        /// v62.0.0 (JSON cut, E5) — the stored id of each named report row
        /// this test thread built (an edition-2 id is computed).
        static NAMED: std::cell::RefCell<std::collections::HashMap<String, String>> =
            std::cell::RefCell::new(std::collections::HashMap::new());
    }

    /// v62.0.0 (E5) — the stored id of the report named `name` (built by
    /// `fix_scores_report` on this thread); the name itself when none was.
    fn rid_named(name: &str) -> String {
        NAMED.with(|m| {
            m.borrow()
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.to_owned())
        })
    }

    /// Build a `scores` report on `dimension`, signed by
    /// `signer`, declaring the target's `subject_key_ids` + `community_id`.
    fn fix_scores_report(
        id: &str,
        signer: &str,
        dimension: &str,
        subject_key_ids: &[&str],
        community_id: Option<&str>,
    ) -> Attestation {
        let mut a = fix_attestation(id, signer, signer, signer);
        // attestation_type stays SCORES (the fix_attestation default).
        let mut env = serde_json::json!({
            "id": id,
            "dimension": dimension,
            "score": 1.0,
            "confidence": 0.9,
        });
        if let Some(c) = community_id {
            // v62.0.0 (E5) — under the switch the room is keyed by its
            // identity-ref (`seed_community_with_founder`).
            let c = if e2::emit_edition2() {
                e2::kid_or_keep(c)
            } else {
                c.to_owned()
            };
            env["community_id"] = serde_json::Value::String(c);
        }
        a.attestation_envelope = env;
        resign_fix(&mut a); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        a.subject_key_ids = subject_key_ids.iter().map(|s| (*s).to_owned()).collect();
        crate::federation::tier_ingest::test_support::reseal(&mut a);
        NAMED.with(|m| m.borrow_mut().insert(id.to_owned(), e2::rid(&a)));
        a
    }

    /// A `delegates_to` edge with explicit `sub_delegation` flag.
    fn fix_delegates_to_sub(
        id: &str,
        granter: &str,
        grantee: &str,
        scope: serde_json::Value,
        sub_delegation: bool,
    ) -> Attestation {
        let mut d = fix_delegates_to(id, granter, grantee, scope);
        d.attestation_envelope["sub_delegation"] = serde_json::Value::Bool(sub_delegation);
        resign_fix(&mut d); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        d
    }

    /// Register a community keyed by `community_id` with `founder` (a
    /// `user`-role founder) in its roster under `founder_only`.
    async fn seed_community_with_founder(
        backend: &SqliteBackend,
        community_id: &str,
        founder: &str,
    ) {
        let signed = crate::federation::tier_ingest::test_support::sign_community(
            community_id,
            crate::federation::types::Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: community_id.into(),
                community_name: "test-community".into(),
                members: vec![crate::federation::types::CommunityMember {
                    key_id: founder.into(),
                    joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                    role: Some("founder".into()),
                }],
                founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                consensus_protocol: "quorum:1/1".into(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        );
        // v62.0.0 (JSON cut, E5) — under the switch the room's key is an
        // edition-2 record and the roster enters as its founder's voice (T1;
        // asserted now); a held caller keeps the JSON doors.
        if e2::emit_edition2() {
            put_e2_key(
                backend,
                community_id,
                crate::federation::types::identity_type::USER,
            )
            .await;
            use crate::federation::edition2::group_fixtures as gf;
            let voices = gf::community_voices(&signed, 1, None, e2::ms(chrono::Utc::now()));
            gf::put_voices(backend, &voices)
                .await
                .expect("seed community");
            return;
        }
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key(community_id, "primitive", community_id),
            })
            .await
            .unwrap();
        backend.put_community(signed).await.expect("seed community");
    }

    #[tokio::test]
    async fn sqlite_moderation_scores_review_full_matrix() {
        let backend = test_backend();
        // `subject` is a user (steward-bound), the content's own subject.
        // `delegate`/`deep` are agent keys; `founder` is the community's
        // steward-bound authority; `rando`/`modkey` are unauthorized.
        put_e2_key(
            &backend,
            "subject",
            crate::federation::types::identity_type::USER,
        )
        .await;
        put_e2_key(
            &backend,
            "founder",
            crate::federation::types::identity_type::USER,
        )
        .await;
        for k in ["delegate", "deep", "rando", "modkey", "agentroot"] {
            put_e2_key(
                &backend,
                k,
                crate::federation::types::identity_type::PRIMITIVE,
            )
            .await;
        }
        seed_community_with_founder(&backend, "comm-1", "founder").await;

        // (a) v21.11.0 (CIRISPersist#517, CC 4.5.5) — as-self subject → REJECT.
        // A reconsideration's REVIEW authority is `is_named_moderator` ONLY;
        // the subject naming ITSELF confers no authority (integrity of the
        // signed subject ≠ authority over the action). `subject` is not a
        // moderator of comm-1, so this is refused (was the spoof: admitted).
        let err = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_scores_report(
                    "r-self",
                    "subject",
                    "reconsideration:case42:v1",
                    &["subject"],
                    None,
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
        assert!(backend
            .get_attestation(&rid_named("r-self"))
            .await
            .unwrap()
            .is_none());

        // (b1) subject-delegated chain (subject → delegate) → REJECT. The
        // subject never held review authority (it is not a moderator), so it
        // cannot delegate it — the delegation row is admissible, but the
        // delegate's reconsideration is not (#517).
        put_voiced(
            &backend,
            &fix_delegates_to(
                "d-rev",
                "subject",
                "delegate",
                serde_json::json!(["message_io", "review"]),
            ),
        )
        .await
        .unwrap();
        let err = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_scores_report(
                    "r-deleg",
                    "delegate",
                    "reconsideration:case42:v1",
                    &["subject"],
                    None,
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
        assert!(backend
            .get_attestation(&rid_named("r-deleg"))
            .await
            .unwrap()
            .is_none());

        // (b1') founder-delegated chain (founder → fdelegate, review over
        // comm-1) → ADMIT. The LEGITIMATE delegated-moderator path: authority
        // roots at a real named moderator (founder) and flows down the
        // review-scoped delegation — proving #517 cut only the subject-self
        // seed, not genuine moderator delegation.
        put_e2_key(
            &backend,
            "fdelegate",
            crate::federation::types::identity_type::PRIMITIVE,
        )
        .await;
        put_voiced(
            &backend,
            // CW-fix1 fixture fix (4u) — the room duty edge NAMES comm-1.
            &fix_delegates_to_in(
                "d-frev",
                "founder",
                "fdelegate",
                serde_json::json!(["message_io", "review"]),
                "comm-1",
            ),
        )
        .await
        .unwrap();
        put_voiced(
            &backend,
            &fix_scores_report(
                "r-fdeleg",
                "fdelegate",
                "reconsideration:case42:v1",
                &[],
                Some("comm-1"),
            ),
        )
        .await
        .expect("(b1') founder-delegated review admitted");
        assert!(backend
            .get_attestation(&rid_named("r-fdeleg"))
            .await
            .unwrap()
            .is_some());

        // (b2) named-moderator: community founder (steward-bound authority)
        // → ADMIT as-self (community-moderation case #95 unblocked).
        put_voiced(
            &backend,
            &fix_scores_report(
                "r-mod",
                "founder",
                "reconsideration:case42:v1",
                &[],
                Some("comm-1"),
            ),
        )
        .await
        .expect("(b2) named-moderator (founder) admitted");
        assert!(backend
            .get_attestation(&rid_named("r-mod"))
            .await
            .unwrap()
            .is_some());

        // (c) no authority (rando, claims subject target) → REJECT.
        let err = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_scores_report(
                    "r-rando",
                    "rando",
                    "reconsideration:case42:v1",
                    &["subject"],
                    None,
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
        assert!(backend
            .get_attestation(&rid_named("r-rando"))
            .await
            .unwrap()
            .is_none());

        // (c2) NOTHING — no subjects, no community → REJECT. THE
        // bypass-closed regression guard: absence is never an admit.
        let err = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_scores_report("r-nothing", "rando", "reconsideration:case42:v1", &[], None),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
        assert!(
            backend
                .get_attestation(&rid_named("r-nothing"))
                .await
                .unwrap()
                .is_none(),
            "(c2) absent principal must REJECT, not admit"
        );

        // (d) scope isolation — a consent_revocation-only delegation from
        // the subject MUST NOT drive a `review`.
        put_voiced(
            &backend,
            &fix_delegates_to(
                "d-wrongscope",
                "subject",
                "modkey",
                serde_json::json!(["consent_revocation"]),
            ),
        )
        .await
        .unwrap();
        let err = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_scores_report(
                    "r-wrongscope",
                    "modkey",
                    "reconsideration:case42:v1",
                    &["subject"],
                    None,
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
        assert!(backend
            .get_attestation(&rid_named("r-wrongscope"))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn sqlite_moderation_scores_moderation_dimension_uses_moderate_scope() {
        // A `moderation:*` scores dimension is gated by the `moderate`
        // scope; a `review`-scoped delegation does NOT satisfy it.
        let backend = test_backend();
        put_e2_key(
            &backend,
            "subject",
            crate::federation::types::identity_type::USER,
        )
        .await;
        put_e2_key(
            &backend,
            "founder",
            crate::federation::types::identity_type::USER,
        )
        .await;
        seed_community_with_founder(&backend, "comm-1", "founder").await;
        put_e2_key(
            &backend,
            "delegate",
            crate::federation::types::identity_type::PRIMITIVE,
        )
        .await;
        // `review`-scoped delegation → cannot drive a `moderation:*` report.
        put_voiced(
            &backend,
            &fix_delegates_to(
                "d-rev2",
                "founder",
                "delegate",
                serde_json::json!(["review"]),
            ),
        )
        .await
        .unwrap();
        let err = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_scores_report(
                    "m-wrongscope",
                    "delegate",
                    "moderation:rogue_action:v1",
                    &["subject"],
                    Some("comm-1"),
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");

        // `moderate`-scoped delegation → ADMIT.
        put_voiced(
            &backend,
            &fix_delegates_to(
                "d-mod",
                "founder",
                "delegate",
                serde_json::json!(["moderate"]),
            ),
        )
        .await
        .unwrap();
        put_voiced(
            &backend,
            &fix_scores_report(
                "m-ok",
                "delegate",
                "moderation:rogue_action:v1",
                &["subject"],
                Some("comm-1"),
            ),
        )
        .await
        .expect("moderate-scoped delegate admitted");
    }

    #[tokio::test]
    async fn sqlite_moderation_scores_depth_cap_rejects() {
        // (e) a `review`-scoped chain deeper than the §11.10 depth cap
        // (MAX_MODERATION_DELEGATION_DEPTH = 5) is refused.
        let backend = test_backend();
        let depth = crate::federation::admission::MAX_MODERATION_DELEGATION_DEPTH;
        // k0 (the steward-bound subject root) → k1 → ... → k(depth+1).
        let n = depth + 2;
        put_e2_key(
            &backend,
            "k0",
            crate::federation::types::identity_type::USER,
        )
        .await;
        let keys: Vec<String> = (0..n).map(|i| format!("k{i}")).collect();
        for k in keys.iter().skip(1) {
            put_e2_key(
                &backend,
                k,
                crate::federation::types::identity_type::PRIMITIVE,
            )
            .await;
        }
        // Every edge `review`-scoped + sub_delegation so only the depth
        // cap (not the deputization gate) is what rejects.
        for i in 0..(n - 1) {
            put_voiced(
                &backend,
                &fix_delegates_to_sub(
                    &format!("d{i}"),
                    &keys[i],
                    &keys[i + 1],
                    serde_json::json!(["review"]),
                    true,
                ),
            )
            .await
            .unwrap();
        }
        // The signer is the too-deep tail key; the root k0 is the subject.
        let err = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_scores_report(
                    "r-toodeep",
                    &keys[n - 1],
                    "reconsideration:case42:v1",
                    &["k0"],
                    None,
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
    }

    #[tokio::test]
    async fn sqlite_moderation_scores_attenuation_and_subdelegation() {
        // (f) ⊆-parent attenuation violation → REJECT; (g) deputization
        // without sub_delegation → REJECT; (h) withdraws on a mid-chain
        // edge → downstream REJECT; (i) non-steward-bound root → REJECT (b).
        let backend = test_backend();
        put_e2_key(
            &backend,
            "subject",
            crate::federation::types::identity_type::USER,
        )
        .await;
        put_e2_key(
            &backend,
            "founder",
            crate::federation::types::identity_type::USER,
        )
        .await;
        seed_community_with_founder(&backend, "comm-1", "founder").await;
        for k in ["mid", "leaf", "agentroot", "agdel"] {
            put_e2_key(
                &backend,
                k,
                crate::federation::types::identity_type::PRIMITIVE,
            )
            .await;
        }

        // (g) deputization without sub_delegation: subject → mid (review,
        // sub_delegation=false), mid → leaf (review). mid may exercise the
        // duty but MUST NOT deputize leaf → leaf REJECT.
        put_voiced(
            &backend,
            &fix_delegates_to_sub(
                "g-1",
                "founder",
                "mid",
                serde_json::json!(["review"]),
                false,
            ),
        )
        .await
        .unwrap();
        put_voiced(
            &backend,
            &fix_delegates_to_sub("g-2", "mid", "leaf", serde_json::json!(["review"]), true),
        )
        .await
        .unwrap();
        let err = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_scores_report(
                    "g-rep",
                    "leaf",
                    "reconsideration:case42:v1",
                    &["subject"],
                    Some("comm-1"),
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_eq!(
            err.kind(),
            "federation_delegated_scope_unauthorized",
            "(g) deputization without sub_delegation must reject downstream"
        );
        // But `mid` itself (the direct delegate) IS admitted.
        put_voiced(
            &backend,
            &fix_scores_report(
                "g-mid",
                "mid",
                "reconsideration:case42:v1",
                &["subject"],
                Some("comm-1"),
            ),
        )
        .await
        .expect("(g) direct delegate (mid) is admitted");

        // (i) non-steward-bound root: agentroot (NOT user-role) → agdel
        // (review). agentroot reaches agdel, but is NOT steward-bound, and is
        // not in any community authority set → agdel REJECT under (b).
        put_voiced(
            &backend,
            &fix_delegates_to("i-1", "agentroot", "agdel", serde_json::json!(["review"])),
        )
        .await
        .unwrap();
        let err = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_scores_report(
                    "i-rep",
                    "agdel",
                    "reconsideration:case42:v1",
                    &["agentroot"],
                    None,
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_eq!(
            err.kind(),
            "federation_delegated_scope_unauthorized",
            "(i) non-steward-bound root cannot confer a delegated duty"
        );

        // (h) withdraws on a mid-chain edge: subject → h_mid (review, sub),
        // h_mid → h_leaf (review). subject then withdraws the subject→h_mid
        // edge → h_leaf REJECT (downstream invalidated).
        for k in ["h_mid", "h_leaf"] {
            put_e2_key(
                &backend,
                k,
                crate::federation::types::identity_type::PRIMITIVE,
            )
            .await;
        }
        put_voiced(
            &backend,
            &fix_delegates_to_sub(
                "h-1",
                "founder",
                "h_mid",
                serde_json::json!(["review"]),
                true,
            ),
        )
        .await
        .unwrap();
        put_voiced(
            &backend,
            &fix_delegates_to_sub(
                "h-2",
                "h_mid",
                "h_leaf",
                serde_json::json!(["review"]),
                true,
            ),
        )
        .await
        .unwrap();
        // h_leaf admitted BEFORE the withdraws.
        put_voiced(
            &backend,
            &fix_scores_report(
                "h-pre",
                "h_leaf",
                "reconsideration:case42:v1",
                &["subject"],
                Some("comm-1"),
            ),
        )
        .await
        .expect("(h) chain valid before withdraws");
        // subject withdraws the subject→h_mid edge (issuer-against-recipient).
        put_voiced(&backend, &{
            let mut w = fix_attestation("h-w", "founder", "h_mid", "founder");
            w.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.into();
            w.attestation_envelope = serde_json::json!({"references_attestation_id": "h-1"});
            resign_fix(&mut w); // envelope changed → re-sign (CC 5.3.2.4.3.1)
            w
        })
        .await
        .expect("founder withdraws own delegation edge");
        let err = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_scores_report(
                    "h-post",
                    "h_leaf",
                    "reconsideration:case42:v1",
                    &["subject"],
                    Some("comm-1"),
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_eq!(
            err.kind(),
            "federation_delegated_scope_unauthorized",
            "(h) withdraws on mid-chain edge invalidates downstream"
        );
    }

    #[tokio::test]
    async fn sqlite_moderation_scores_attenuation_violation_rejects() {
        // (f) focused: child edge scope-set NOT ⊆ parent → REJECT.
        let backend = test_backend();
        put_e2_key(
            &backend,
            "subject",
            crate::federation::types::identity_type::USER,
        )
        .await;
        for k in ["mid", "leaf"] {
            put_e2_key(
                &backend,
                k,
                crate::federation::types::identity_type::PRIMITIVE,
            )
            .await;
        }
        // subject → mid grants {review} (sub_delegation).
        put_voiced(
            &backend,
            &fix_delegates_to_sub(
                "att-1",
                "subject",
                "mid",
                serde_json::json!(["review"]),
                true,
            ),
        )
        .await
        .unwrap();
        // mid → leaf grants {review, moderate} — EXPANDS beyond parent's
        // {review}; the review-scoped edge is present but the scope-set is
        // not ⊆ parent → attenuation rejects the traversal to leaf.
        put_voiced(
            &backend,
            &fix_delegates_to_sub(
                "att-2",
                "mid",
                "leaf",
                serde_json::json!(["review", "moderate"]),
                true,
            ),
        )
        .await
        .unwrap();
        let err = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_scores_report(
                    "att-rep",
                    "leaf",
                    "reconsideration:case42:v1",
                    &["subject"],
                    None,
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_eq!(
            err.kind(),
            "federation_delegated_scope_unauthorized",
            "(f) child scope-set must be ⊆ parent scope-set"
        );
    }

    // ── v9.0.0 (CC 3.2 / CC 3.4.7.1) — steward-binding precondition for
    // non-infrastructure community membership. A node/agent roster member of a
    // non-infra community MUST be steward-bound; infra communities + pure
    // user/canonical participation are not over-rejected.

    /// Register a `user`-role key, a node-only key, and an agent key.
    async fn seed_ob_keys(backend: &SqliteBackend) {
        // v62.0.0 (E5) — an edition-2 `key:record` (hardware evidence is not
        // carried by the fixture record).
        put_e2_key(
            backend,
            "ob-owner",
            crate::federation::types::identity_type::USER,
        )
        .await;
        // v62.0.0 (E5) — an edition-2 `key:record` (hardware evidence is not
        // carried by the fixture record).
        put_e2_key(
            backend,
            "ob-node",
            crate::federation::types::identity_type::NODE,
        )
        .await;
        // v62.0.0 (E5) — an edition-2 `key:record` (hardware evidence is not
        // carried by the fixture record).
        put_e2_key(
            backend,
            "ob-agent",
            crate::federation::types::identity_type::AGENT,
        )
        .await;
    }

    // ─── v6.7.0 Lane G (CEG 1.0-RC5) — consent clauses ─────────────

    use crate::federation::types::consent_record;

    // ── Clause 2 (#146 Ask 5, CEG §5.6.8.7) — consent_record ───────

    /// Build a `consent_record` `scores` attestation envelope + row.
    fn consent_record_row(
        id: &str,
        subject: &str,
        stance: &str,
        tier: &str,
        include_required: bool,
    ) -> Attestation {
        let mut env = serde_json::json!({
            "id": id,
            "subject_kind": consent_record::SUBJECT_KIND,
            "stance": stance,
            "dimension": "consent:partnership_grant:v1",
        });
        if include_required {
            env["subject_key_id"] = serde_json::json!(subject);
            env["asserted_at"] = serde_json::json!("2026-06-01T00:00:00Z");
        }
        let mut a = fix_attestation(id, subject, "registry-steward", "registry-steward");
        a.attestation_envelope = env;
        resign_fix(&mut a); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        a.tier = tier.to_string();
        // A local-tier row must be cohort_scope=self (the v4.0 read-gate);
        // federation rows keep the fixture default.
        if tier == crate::federation::types::attestation_tier::LOCAL {
            a.cohort_scope = crate::federation::types::cohort_scope::SELF.to_string();
            crate::federation::tier_ingest::test_support::reseal(&mut a);
        }
        a
    }

    async fn consent_backend() -> SqliteBackend {
        let backend = test_backend();
        for k in ["registry-steward", "subject-key"] {
            put_e2_key(
                &backend,
                k,
                crate::federation::types::identity_type::PRIMITIVE,
            )
            .await;
        }
        backend
    }

    #[tokio::test]
    async fn consent_record_missing_required_field_rejected() {
        let backend = consent_backend().await;
        let row = consent_record_row(
            "cr-2",
            "subject-key",
            consent_record::stance::GRANTED,
            crate::federation::types::attestation_tier::FEDERATION,
            false, // omit subject_key_id / asserted_at
        );
        let err = NotLanded::of(
            &backend,
            put_voiced(&backend, &row).await,
            "the row does not land",
        )
        .await;
        assert!(
            matches!(err.error(), Some(crate::federation::Error::InvalidArgument(m)) if m.contains("subject_key_id")),
            "missing required field rejected, got {err:?}"
        );
    }

    /// v12.6.0 (CIRISPersist#171, §10.1.3) — the `put_attestation(tier=local)`
    /// bypass is CLOSED for *bare* subject-side revocations too (not only the
    /// consent_record ceremony): a `consent:state:revoked` row whose writer ∈
    /// `subject_key_ids` at local tier is hybrid-verified at ingest — a valid
    /// signature transits, a forged one is rejected.
    #[tokio::test]
    async fn bare_subject_side_revocation_via_put_attestation_gated() {
        let backend = consent_backend().await;
        let mut row = fix_attestation("bare-rev", "subject-key", "registry-steward", "subject-key");
        // v31.0.0 (CIRISPersist#598) — the signed instant must equal the column.
        row.asserted_at =
            crate::federation::admission::truncate_to_substrate_resolution(row.asserted_at);
        row.attestation_envelope = serde_json::json!({
            "id": "bare-rev", "dimension": "consent:state:revoked:v1",
            "score": 1.0, "confidence": 0.9,
            crate::federation::envelope::paths::ASSERTED_AT: crate::federation::admission::render_signed_instant(row.asserted_at),
        });
        row.subject_key_ids = vec!["subject-key".into()];
        row.tier = crate::federation::types::attestation_tier::LOCAL.into();
        row.cohort_scope = crate::federation::types::cohort_scope::SELF.to_string();
        resign_fix(&mut row); // envelope changed → re-sign
        put_voiced(&backend, &row)
            .await
            .expect("crypto-valid bare subject-side revocation transits at local tier");
        // E5-fix1 (round 3) — the forged-`scrub_signature_classical` leg is
        // DELETED (ruling 4): under edition 2 the row's proof is its carried
        // statement, and a JSON signature column is no proof at all, so
        // forging it re-offers the same statement (`Voice`, not a refusal).
        // The statement door's own forged-signature witnesses cover it.
    }

    #[tokio::test]
    async fn consent_record_revoked_federation_tier_admits() {
        let backend = consent_backend().await;
        let row = consent_record_row(
            "cr-5",
            "subject-key",
            consent_record::stance::REVOKED,
            crate::federation::types::attestation_tier::FEDERATION,
            true,
        );
        put_voiced(&backend, &row)
            .await
            .expect("revoked/federation consent_record admits");
    }

    #[tokio::test]
    async fn consent_record_bad_stance_rejected() {
        let backend = consent_backend().await;
        let row = consent_record_row(
            "cr-6",
            "subject-key",
            "maybe",
            crate::federation::types::attestation_tier::FEDERATION,
            true,
        );
        let err = NotLanded::of(
            &backend,
            put_voiced(&backend, &row).await,
            "the row does not land",
        )
        .await;
        assert!(
            matches!(err.error(), Some(crate::federation::Error::InvalidArgument(m)) if m.contains("closed set")),
            "out-of-closed-set stance rejected, got {err:?}"
        );
    }

    /// #238 (CC 4.5.4 / §11.11) — the no-moderator-no-federate substrate gate,
    /// decision-table style. A `community` federates ONLY while ≥1 steward-bound
    /// authority root (a live named `moderate`-holder) exists; infrastructure
    /// communities are EXEMPT. Enforcement lives at the federation-apply
    /// chokepoint ([`check_no_moderator_federate_apply`]); the admission
    /// predicate ([`check_no_moderator_federate_admission`]) is its primitive.
    #[tokio::test]
    async fn no_moderator_federate_gate_decision_table() {
        use crate::federation::admission::{
            check_no_moderator_federate_admission, check_no_moderator_federate_admission_by_id,
            check_no_moderator_federate_apply, MEMBER_ROLE_FOUNDER,
        };
        use crate::federation::types::identity_type;

        // Build a community `cid` founded (founder_only) by `founder` of
        // identity_type `founder_it`, optionally infra-labeled. Registers the
        // community + founder keys and STORES the record (put_community itself
        // does not gate on moderator existence — the apply path does).
        async fn seed(
            backend: &SqliteBackend,
            cid: &str,
            founder: &str,
            founder_it: &str,
            infra: bool,
        ) -> crate::federation::types::Community {
            // v62.0.0 (JSON cut, E5) — edition-2 key records; the roster
            // enters as its voices (T1) and the record is returned keyed by
            // identity-refs.
            put_e2_key(
                backend,
                cid,
                if infra {
                    // SecReview F2: a self-claimed substrate_persist key.
                    identity_type::SUBSTRATE_PERSIST
                } else {
                    identity_type::USER
                },
            )
            .await;
            put_e2_key(backend, founder, founder_it).await;
            if infra {
                for f in
                    &crate::federation::tier_ingest::test_support::FIXTURE_INFRASTRUCTURE_FOUNDERS
                        [1..]
                {
                    put_e2_key(backend, f, identity_type::USER).await;
                }
            }
            let policy_blob =
                infra.then(|| serde_json::json!({ "cohort_subkind": "infrastructure" }));
            let community = crate::federation::types::Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: cid.into(),
                community_name: "dt".into(),
                members: {
                    let mut m = vec![crate::federation::types::CommunityMember {
                        key_id: founder.into(),
                        joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                        role: Some(MEMBER_ROLE_FOUNDER.into()),
                    }];
                    // v62.0.0 (TR-fix2; CC rc21 3.2 T7) — an infrastructure
                    // fixture counts at `quorum:2/3`: two more founders.
                    if infra {
                        for f in &crate::federation::tier_ingest::test_support::FIXTURE_INFRASTRUCTURE_FOUNDERS[1..] {
                            m.push(crate::federation::types::CommunityMember {
                                key_id: (*f).into(),
                                joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                                role: Some(MEMBER_ROLE_FOUNDER.into()),
                            });
                        }
                    }
                    m
                },
                founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                consensus_protocol: crate::federation::tier_ingest::test_support::fixture_protocol(
                    policy_blob.as_ref(),
                    // v61 (CIRISPersist#1123): founder_only is refused
                    // above the family; a one-founder room's protocol.
                    "quorum:1/1",
                ),
                policy_blob,
                persist_row_hash: String::new(),
            };
            use crate::federation::edition2::group_fixtures as gf;
            let signed =
                crate::federation::tier_ingest::test_support::sign_community(cid, community);
            gf::put_voices(
                backend,
                &gf::community_voices(&signed, 1, None, e2::ms(chrono::Utc::now())),
            )
            .await
            .expect("record stored (the roster door is not the moderator gate)");
            gf::community_with_kids(&signed.community)
        }

        let b = test_backend();

        // ── admission predicate (the reusable primitive) ────────────────────
        // (1) user founder = steward-bound authority root = zero-hop named
        //     moderator → ADMIT.
        let c_ok = seed(&b, "dt-ok", "dt-user", identity_type::USER, false).await;
        check_no_moderator_federate_admission(&b, &c_ok)
            .await
            .expect("steward-bound (user) founder ⇒ has a moderator ⇒ may federate");

        // (2) primitive founder = passes the steward-binding gate (not
        //     node/agent, out of its scope) but is NOT steward-bound ⇒ NO named
        //     moderator ⇒ REJECT, fail-secure.
        let c_no = seed(&b, "dt-no", "dt-prim", identity_type::PRIMITIVE, false).await;
        let err = check_no_moderator_federate_admission(&b, &c_no)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::federation::Error::CommunityHasNoModerator { .. }
            ),
            "moderator-less community refused, got {err:?}"
        );
        assert_eq!(err.kind(), "federation_community_no_moderator");

        // (3) v62.0.0 (CC rc20 3.4.7.1 / 3.2, #1274) — a SELF-DECLARED
        //     infrastructure community (its key self-claims substrate_persist,
        //     its founder is no person, it roots nowhere) is NOT exempt: the
        //     exemption is the authorized-infrastructure predicate's (a
        //     conformant record rooted in this node's trust set), never a key
        //     type. Until v62 this leg asserted the exemption.
        let c_infra = seed(&b, "dt-infra", "dt-iprim", identity_type::PRIMITIVE, true).await;
        assert!(matches!(
            check_no_moderator_federate_admission(&b, &c_infra).await,
            Err(crate::federation::Error::CommunityHasNoModerator { .. })
        ));
        //     A conformant, rooted infrastructure room is authorized.
        let rooted_id =
                crate::federation::canonical_community_invariants::bodies::rooted_infrastructure_room_e2(
                    &b,
                    "dt-rooted",
                    &[],
                    "dt-rooted",
                )
                .await;
        let rooted = b
            .lookup_community(&rooted_id)
            .await
            .unwrap()
            .expect("the rooted room is held");
        assert!(
            crate::federation::admission::is_authorized_infrastructure_community(&b, &rooted)
                .await
                .unwrap()
        );
        check_no_moderator_federate_admission(&b, &rooted)
            .await
            .expect("authorized infrastructure community is exempt from the moderator gate");

        // ── federation-apply chokepoint (points i + ii unified) ─────────────
        // A federation-tier row keyed on the moderator-less community → REJECT.
        let mut row = fix_attestation("dt-apply", "dt-prim", "dt-prim", "dt-prim");
        row.attestation_envelope = serde_json::json!({
            "id": "dt-apply", "dimension": "identity_binding:v1", "community_id": e2::kid("dt-no")
        });
        let err = check_no_moderator_federate_apply(&b, &row)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::federation::Error::CommunityHasNoModerator { .. }
            ),
            "federation-apply step keyed on a moderator-less community is refused"
        );
        // A LOCAL-tier row keyed on it → no-op (local writes are not a
        // federation apply step).
        let mut local_row = row.clone();
        local_row.tier = crate::federation::types::attestation_tier::LOCAL.into();
        check_no_moderator_federate_apply(&b, &local_row)
            .await
            .expect("local-tier row is not a federation apply step");
        // A row keyed on the MODERATORED community → ADMIT.
        let mut live_row = row.clone();
        live_row.attestation_envelope = serde_json::json!({
            "id": "dt-apply2", "dimension": "identity_binding:v1", "community_id": e2::kid("dt-ok")
        });
        check_no_moderator_federate_apply(&b, &live_row)
            .await
            .expect("moderatored community may continue to federate");
        // No community_id + unknown community_id → out of scope (Ok).
        let mut bare = row.clone();
        bare.attestation_envelope =
            serde_json::json!({ "id": "x", "dimension": "identity_binding:v1" });
        check_no_moderator_federate_apply(&b, &bare)
            .await
            .expect("no community_id ⇒ not keyed on a community ⇒ no-op");
        check_no_moderator_federate_admission_by_id(&b, "no-such")
            .await
            .expect("unknown community ⇒ out of scope ⇒ no-op");
    }

    /// #369 (CC 4.5.4 / §11.11) — BROADENED apply-gate keying: a federation
    /// apply step is keyed on `C` under ANY of the substrate's community-
    /// reference shapes, not only a literal `attestation_envelope.community_id`.
    /// Decision table over the membership-attestation shapes: row endpoints
    /// (`attested_key_id` / `attesting_key_id` resolving as a stored
    /// community — the "subject doubles as the membership target" read-gate
    /// rule), `subject_key_ids` entries, and the sibling envelope field names
    /// (`community_key_id` / `cohort_key_id`). Plus the negative half:
    /// local-tier + storage-only community ops stay untouched.
    #[tokio::test]
    async fn no_moderator_federate_gate_broadened_keying_decision_table() {
        use crate::federation::admission::{
            check_no_moderator_federate_apply, no_moderator_federate_verdict, MEMBER_ROLE_FOUNDER,
        };
        use crate::federation::types::identity_type;

        let b = test_backend();

        // Seed a MODERATOR-LESS community (primitive founder — passes the
        // steward-binding storage gate, but is NOT steward-bound ⇒ no
        // zero-hop moderator) and a MODERATORED one (user founder).
        // v62.0.0 (JSON cut, E5) — edition-2 keys; the roster enters as its
        // voices (T1). Every id below is the identity-ref (`e2::kid`).
        async fn seed(backend: &SqliteBackend, cid: &str, founder: &str, founder_it: &str) {
            put_e2_key(backend, cid, identity_type::USER).await;
            put_e2_key(backend, founder, founder_it).await;
            use crate::federation::edition2::group_fixtures as gf;
            let signed = crate::federation::tier_ingest::test_support::sign_community(
                cid,
                crate::federation::types::Community {
                    prev_head_digest: String::new(),
                    charter_digest: String::new(),
                    community_key_id: cid.into(),
                    community_name: "bk".into(),
                    members: vec![crate::federation::types::CommunityMember {
                        key_id: founder.into(),
                        joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                        role: Some(MEMBER_ROLE_FOUNDER.into()),
                    }],
                    founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                    consensus_protocol: "quorum:1/1".into(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            );
            gf::put_voices(
                backend,
                &gf::community_voices(&signed, 1, None, e2::ms(chrono::Utc::now())),
            )
            .await
            .expect("the roster door is NOT the moderator gate");
        }
        seed(&b, "bk-no", "bk-prim", identity_type::PRIMITIVE).await;
        seed(&b, "bk-ok", "bk-user", identity_type::USER).await;

        // The rows below feed the pure apply check only (no door, no
        // signature), so they are not re-sealed after their edits.
        let (no, ok, prim) = (e2::kid("bk-no"), e2::kid("bk-ok"), e2::kid("bk-prim"));
        let refused = |err: crate::federation::Error, shape: &str| {
            assert!(
                matches!(
                    err,
                    crate::federation::Error::CommunityHasNoModerator { .. }
                ),
                "{shape}: moderator-less community must refuse, got {err:?}"
            );
        };

        // (1) MEMBERSHIP shape — federation-tier row attested TO the
        //     moderator-less community (no envelope community field) → REJECT.
        let bare_env = serde_json::json!({ "id": "bk-1", "dimension": "identity_binding:v1" });
        let mut row = fix_attestation("bk-1", "bk-prim", "bk-no", "bk-prim");
        row.attestation_envelope = bare_env.clone();
        refused(
            check_no_moderator_federate_apply(&b, &row)
                .await
                .unwrap_err(),
            "attested_key_id = C",
        );
        // Same shape onto the MODERATORED community → ADMIT.
        let mut ok_row = fix_attestation("bk-2", "bk-user", "bk-ok", "bk-user");
        ok_row.attestation_envelope = bare_env.clone();
        check_no_moderator_federate_apply(&b, &ok_row)
            .await
            .expect("membership-shaped row onto a moderatored community is admitted");
        // LOCAL tier onto the moderator-less community → untouched.
        let mut local = row.clone();
        local.tier = crate::federation::types::attestation_tier::LOCAL.into();
        check_no_moderator_federate_apply(&b, &local)
            .await
            .expect("local-tier membership row is not a federation apply step");

        // (2) EMITTED-BY-C shape — attesting_key_id = the community → REJECT.
        let mut by_c = fix_attestation("bk-3", "bk-no", "bk-prim", "bk-no");
        by_c.attestation_envelope = bare_env.clone();
        refused(
            check_no_moderator_federate_apply(&b, &by_c)
                .await
                .unwrap_err(),
            "attesting_key_id = C",
        );

        // (3) subject_key_ids shape → REJECT; non-community subjects fail-open.
        let mut subj = fix_attestation("bk-4", "bk-prim", "bk-prim", "bk-prim");
        subj.attestation_envelope = bare_env.clone();
        subj.subject_key_ids = vec!["not-a-community".into(), no.clone()];
        refused(
            check_no_moderator_federate_apply(&b, &subj)
                .await
                .unwrap_err(),
            "subject_key_ids ∋ C",
        );
        let mut subj_ok = subj.clone();
        subj_ok.subject_key_ids = vec!["not-a-community".into(), ok.clone()];
        check_no_moderator_federate_apply(&b, &subj_ok)
            .await
            .expect("subject-keyed row onto a moderatored community is admitted");

        // (4) Sibling envelope field names (`community_key_id` / `cohort_key_id`)
        //     → REJECT on the moderator-less community.
        for field in ["community_key_id", "cohort_key_id"] {
            let mut env_row = fix_attestation("bk-5", "bk-prim", "bk-prim", "bk-prim");
            env_row.attestation_envelope = serde_json::json!({
                "id": "bk-5", "dimension": "identity_binding:v1", field: no.clone()
            });
            refused(
                check_no_moderator_federate_apply(&b, &env_row)
                    .await
                    .unwrap_err(),
                field,
            );
        }

        // (5) Storage-only community ops on the moderator-less community stay
        //     untouched: the record can be re-stored (roster rewrite) and its
        //     membership revocations recorded — loss-processing + the CC
        //     4.5.13 recovery must not be blocked by the federate gate.
        // v62.0.0 (E5) — the removal is its `membership:removal` voice by
        // the leaving founder, naming the held roster head (T1). (The
        // earlier roster re-store is gone: a re-offer of version 1 at a new
        // instant is another row, not a re-store.)
        {
            use crate::federation::edition2::group_fixtures as gf;
            let removal =
                crate::federation::tier_ingest::test_support::sign_community_membership_revocation(
                    &prim,
                    crate::federation::types::CommunityMembershipRevocation {
                        community_key_id: no.clone(),
                        removed_identity_key_id: prim.clone(),
                        removed_at: chrono::Utc::now(),
                        effective_at: chrono::Utc::now(),
                        reason: Some("storage-only membership op stays ungated".into()),
                        witness_set: Vec::new(),
                        persist_row_hash: String::new(),
                    },
                );
            let head = gf::held_head(&b, &no).await.map(|(h, _)| h);
            gf::put_voices(
                &b,
                &gf::community_revocation_voices(&removal, head.as_ref()),
            )
            .await
            .expect(
                "membership revocation on a moderator-less community is storage, not federation",
            );
        }

        // (6) The drivable verdict mirrors the gate decision exactly.
        let v = no_moderator_federate_verdict(&b, &no).await.unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "admitted": false, "community_known": true,
                "reason": "federation_community_no_moderator"
            })
        );
        let v = no_moderator_federate_verdict(&b, &ok).await.unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "admitted": true, "community_known": true })
        );
        let v = no_moderator_federate_verdict(&b, "no-such").await.unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "admitted": true, "community_known": false })
        );
    }

    /// v16 (CIRISPersist#431) — the compare surface REFUSES a corpus row
    /// it cannot round-trip back to the verify-core witness shape
    /// (substrate corruption), rather than classifying over it. This is
    /// the "never compare an unverifiable witness" assertion: the F-5
    /// rule means every stored row passed the gate, so the only
    /// unverifiable row is a corrupted one — and it errors, fail-closed.
    #[tokio::test]
    async fn compare_refuses_corrupted_witness_row() {
        use crate::federation::FederationDirectory;
        let backend = test_backend();
        // Simulate at-rest corruption: a row whose merkle_root column is
        // not 64 hex chars (unreachable via put_wholeness_witness — the
        // gate writes only encode_root_hex output).
        backend
            .test_execute(
                "INSERT INTO wholeness_witness_corpus (peer_id, epoch_id, observed_at_unix_ms, \
                    claim_namespaces, merkle_root, leaf_count, witness_version, signature, \
                    signature_ml_dsa_65, pqc_key_id, admitted_at) \
                 VALUES ('corrupt-peer', 1, 1000, '[\"scores:medical\"]', 'not-hex', 1, 1, \
                    'AA==', 'AA==', 'k', '2026-01-01T00:00:00+00:00')",
            )
            .await;
        let peers = ["corrupt-peer".to_string()];
        let err = backend
            .compare_stored_witnesses(Some(&peers))
            .await
            .expect_err("a corrupted row REFUSES comparison (never a verdict)");
        assert_eq!(err.kind(), "witness_admit_malformed_root");
        // The N4 read-back refuses identically.
        let err = backend
            .list_witness_equivocations("corrupt-peer")
            .await
            .expect_err("read-back refuses the corrupted row too");
        assert_eq!(err.kind(), "witness_admit_malformed_root");
    }

    // ── CIRISConstitution#23 (CC 1.13.3.3 / CC 3.2) — the owner seat ──

    /// Build an OWNER-BINDING `delegates_to(owner → node)` carrying the CC
    /// 1.13.3.3 / CC 3.2 ownership dimension (what `owner_of` keys on) with
    /// infra-only scope, re-signed for the
    /// federation-tier ingest gate. Distinct from [`fix_node_delegates_to`],
    /// which builds a plain (non-ownership) infra delegation.
    fn fix_owner_binding(id: &str, owner: &str, node: &str) -> Attestation {
        use crate::federation::types::{attestation_type, delegation_scope as ds, owner_binding};
        let mut att = fix_attestation(id, owner, node, owner);
        att.attestation_type = attestation_type::DELEGATES_TO.into();
        crate::federation::tier_ingest::test_support::reseal(&mut att);
        att.attestation_envelope = serde_json::json!({
            "id": id,
            "kind": "delegates_to",
            "dimension": owner_binding::DIMENSION,
            "delegation_purpose": owner_binding::PURPOSE,
            "scope": [ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
        });
        resign_fix(&mut att); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        att
    }

    /// Register a SECOND `user`-role key — a distinct would-be owner.
    async fn seed_second_owner(backend: &SqliteBackend, key_id: &str) {
        // v62.0.0 (E5) — an edition-2 `key:record` (hardware evidence is not
        // carried by the fixture record).
        put_e2_key(
            backend,
            key_id,
            crate::federation::types::identity_type::USER,
        )
        .await;
    }

    /// v13.3.0 (CIRISPersist#378) — the owner-binding built with the **CC
    /// 2.4.1.2 canonical marker only** (`delegation_purpose: "owner_binding"`,
    /// **no `dimension`**) — the shape a raw `emit_attestation_self` `delegates_to`
    /// carries, and exactly what CIRISConformance `test_551` probes. Before the
    /// fix, the owner fold keyed on the internal dimension alone and this path
    /// was invisible to it.
    fn fix_owner_binding_cc(id: &str, owner: &str, node: &str) -> Attestation {
        use crate::federation::types::{attestation_type, delegation_scope as ds, owner_binding};
        let mut att = fix_attestation(id, owner, node, owner);
        att.attestation_type = attestation_type::DELEGATES_TO.into();
        crate::federation::tier_ingest::test_support::reseal(&mut att);
        // CC 2.4.1.2 marker ONLY (no `dimension`). Carries the infra scopes so
        // it clears the node-agency gate and is stored, so the owner seat reads
        // it (the marker recognition is the thing being proven).
        att.attestation_envelope = serde_json::json!({
            "id": id,
            "kind": "delegates_to",
            "delegation_purpose": owner_binding::CC_DELEGATION_PURPOSE,
            "scope": [ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
        });
        resign_fix(&mut att);
        att
    }

    /// v13.3.0 (CIRISPersist#378) — `owner_of` fires on the **CC-marker
    /// raw-emit path** (`delegation_purpose: "owner_binding"`, no dimension),
    /// not only persist's internal-dimension `steward_bind` path (the bypass
    /// CIRISConformance `test_551` caught).
    ///
    /// **I2841** (v62.0.0, kernel pass 2, KERNEL_SEAMS B1 / C557) — a second,
    /// DIFFERENT owner via the same path is no longer refused
    /// (`federation_node_already_owned` is gone): its binding is HELD. Both
    /// bindings are cosigned by the node (the fixture sealer co-scrubs an
    /// owner binding by its node), so the kernel's owner seat counts two
    /// owners and reads the node as unowned — `AmbiguousNodeOwner`,
    /// fail-closed — never as whichever binding arrived first.
    #[tokio::test]
    async fn i2841_a_second_distinct_owner_via_cc_marker_is_held_and_reads_unowned() {
        use crate::federation::admission::owner_of;
        let backend = test_backend();
        seed_ob_keys(&backend).await;
        seed_second_owner(&backend, "ob-owner2").await;

        // First owner-binding (CC marker, no dimension) admits; owner_of resolves.
        // E5-fix1 (round 3; K2.api) — the binding counts with the node's own
        // voice (CC 3.2 / C557): K2's shared helper puts both.
        crate::federation::tier_ingest::test_support::put_sealed_owner_binding(
            &backend,
            &fix_owner_binding_cc("ob-cc1", "ob-owner", "ob-node"),
            "ob-node",
        )
        .await
        .unwrap();
        assert_eq!(
            owner_of(&backend, &e2::kid("ob-node")).await.unwrap(),
            Some(e2::kid("ob-owner")),
            "owner_of must resolve the CC-marker owner-binding"
        );

        // E5-fix1 (round 3) — I2841 as its doc states it (kernel B1 / C557):
        // a second, DIFFERENT owner is never refused for being second. Cosigned
        // by the node as well, it is a second COUNTED owner, and the owner seat
        // reads the node as unowned (fail-closed), never as the first arrival.
        crate::federation::edition2::fixture_switch::land_owner_binding(
            &backend,
            &fix_owner_binding_cc("ob-cc2", "ob-owner2", "ob-node"),
            "ob-node",
        )
        .await
        .expect("I2841: a second owner's binding is not refused");
        let read = owner_of(&backend, &e2::kid("ob-node")).await;
        assert!(
            matches!(
                read,
                Ok(None) | Err(crate::federation::Error::AmbiguousNodeOwner { .. })
            ),
            "I2841: two counted owners read as unowned, got {read:?}"
        );
    }

    /// Ownership is transferable, not permanent: after the incumbent binding
    /// lapses (expiry → non-live), a DIFFERENT owner's binding is the one the
    /// owner seat counts. (v62.0.0: no gate stands between the two; the
    /// kernel's owner seat presents only a live binding.)
    #[tokio::test]
    async fn the_owner_after_the_incumbent_expires_is_the_new_owner() {
        use crate::federation::admission::owner_of;
        let backend = test_backend();
        seed_ob_keys(&backend).await;
        seed_second_owner(&backend, "ob-owner2").await;

        // An already-expired incumbent binding. v31.0.0 (CIRISPersist#598) —
        // this comment used to read "expires_at is a row field, not in the
        // signed envelope, so the ingest signature is unaffected". That
        // sentence WAS the vulnerability: an expiry only the column carried was
        // an unsigned mute button, since every consent fold DROPS an expired
        // row. `expires_at` is now bound in both directions, so moving it is a
        // re-sign trigger exactly like moving the envelope.
        let mut expired = fix_owner_binding("ob-b1", "ob-owner", "ob-node");
        expired.expires_at = Some("2020-01-01T00:00:00Z".parse().unwrap());
        resign_fix(&mut expired);
        // E5-fix1 (round 3; K2.api) — with the node's own voice; an expired
        // binding's outcome is not asserted, only the read.
        crate::federation::edition2::fixture_switch::land_owner_binding(
            &backend, &expired, "ob-node",
        )
        .await
        .unwrap();
        // Expired → non-live → node reads as unowned.
        assert_eq!(owner_of(&backend, &e2::kid("ob-node")).await.unwrap(), None);

        // A different owner may now bind.
        crate::federation::tier_ingest::test_support::put_sealed_owner_binding(
            &backend,
            &fix_owner_binding("ob-b2", "ob-owner2", "ob-node"),
            "ob-node",
        )
        .await
        .unwrap();
        assert_eq!(
            owner_of(&backend, &e2::kid("ob-node")).await.unwrap(),
            Some(e2::kid("ob-owner2"))
        );
    }

    /// (CIRISPersist#593) — the read cost of the new incoming-retraction
    /// clause, MEASURED against this backend's own directory-read counters, and
    /// the proof that the predicate walk still stops at the first hit.
    #[tokio::test]
    async fn moderation_walk_read_cost_sqlite_593() {
        let backend = test_backend();
        crate::federation::admission::moderation_walk_liveness_test_support::exercise_moderation_walk_read_cost(
            &backend, "suite",
        )
        .await;
    }

    /// reachable_under_scope_with_reasons (#272): the refusal-reason
    /// companion classifies each "no" — Reachable / MissingScope /
    /// RetractedAtRoot / SignerUnreached / NoTrustRoots — and stays
    /// byte-identical to the bool walk on the Reachable case. Distinct
    /// key pairs isolate the scenarios in one backend.
    #[tokio::test]
    async fn reachable_under_scope_with_reasons_classifies_refusals() {
        use crate::federation::admission::{
            reachable_under_scope, reachable_under_scope_with_reasons, ReachabilityVerdict,
            DELEGATION_SCOPE_MODERATE, DELEGATION_SCOPE_REVIEW, MAX_MODERATION_DELEGATION_DEPTH,
        };
        let backend = test_backend();
        for k in [
            "ar-root", "ar-tgt", "br-root", "br-tgt", "cr-root", "cr-mid", "cr-tgt", "dr-iso",
            "dr-tgt",
        ] {
            put_e2_key(
                &backend,
                k,
                crate::federation::types::identity_type::PRIMITIVE,
            )
            .await;
        }
        // A scope-bearing (`moderate`) delegation edge.
        let delegate = |id: &str, granter: &str, grantee: &str| {
            let mut d = fix_attestation(id, granter, grantee, granter);
            d.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
            crate::federation::tier_ingest::test_support::reseal(&mut d);
            // E5-fix2 (round 6) — no self-naming `references_attestation_id`:
            // an edition-2 row cannot name its own (node-computed) id.
            d.attestation_envelope = serde_json::json!({
                "scope": [DELEGATION_SCOPE_MODERATE],
                "sub_delegation": true,
            });
            resign_fix(&mut d);
            d
        };
        // E5-fix2 (round 6) — the retraction is the granter's `withdraws`
        // composer naming the edge by its row id (`refs.target`, CC 2.6.1.7).
        let br_d = delegate("br-d", "br-root", "br-tgt");
        let br_w = fix_withdraws("br-w", "br-root", &e2::rid(&br_d));
        for a in [
            delegate("ar-d", "ar-root", "ar-tgt"), // Reachable / MissingScope pair
            br_d,                                  // RetractedAtRoot pair
            br_w,                                  // … retracted
            delegate("cr-d", "cr-root", "cr-mid"), // SignerUnreached: edge, but not to tgt
        ] {
            put_voiced(&backend, &a).await.unwrap();
        }
        let depth = MAX_MODERATION_DELEGATION_DEPTH;
        let verdict = |issuer: &'static str, tgt: &'static str, scope: &'static str| {
            let b = &backend;
            async move {
                // E5-fix2 (round 6) — keys are named by their identity-refs.
                reachable_under_scope_with_reasons(b, &e2::kid(issuer), &e2::kid(tgt), scope, depth)
                    .await
                    .unwrap()
            }
        };

        // Reachable — and consistent with the bool walk.
        assert_eq!(
            verdict("ar-root", "ar-tgt", DELEGATION_SCOPE_MODERATE).await,
            ReachabilityVerdict::Reachable
        );
        assert!(reachable_under_scope(
            &backend,
            &e2::kid("ar-root"),
            &e2::kid("ar-tgt"),
            DELEGATION_SCOPE_MODERATE,
            depth
        )
        .await
        .unwrap());
        // MissingScope — edge to target exists but does not carry `review`.
        assert_eq!(
            verdict("ar-root", "ar-tgt", DELEGATION_SCOPE_REVIEW).await,
            ReachabilityVerdict::MissingScope
        );
        // RetractedAtRoot — scope-bearing edge to target, but withdrawn.
        assert_eq!(
            verdict("br-root", "br-tgt", DELEGATION_SCOPE_MODERATE).await,
            ReachabilityVerdict::RetractedAtRoot
        );
        // SignerUnreached — issuer delegates, but no path reaches the target.
        assert_eq!(
            verdict("cr-root", "cr-tgt", DELEGATION_SCOPE_MODERATE).await,
            ReachabilityVerdict::SignerUnreached
        );
        // NoTrustRoots — issuer emitted no delegation edges at all.
        assert_eq!(
            verdict("dr-iso", "dr-tgt", DELEGATION_SCOPE_MODERATE).await,
            ReachabilityVerdict::NoTrustRoots
        );
    }

    /// #288 (CC 3.4.1/3.4.3/3.4.5) — reserved-prefix admission on the
    /// attestation_TYPE, keyed on the attesting key's identity_type:
    /// `accord:*`→accord_holder, `system:*`→substrate_persist,
    /// `hard_case:*`→substrate_persist, `capacity:*`→no self-emission.
    /// Reproduces the issue's three repro cases + the authorized contrast.
    #[tokio::test]
    async fn check_reserved_prefix_admission_enforces_cc_3_4_x_288() {
        use crate::federation::admission::check_reserved_prefix_admission;
        let backend = test_backend();
        for (k, it) in [
            ("rp-agent", "agent"),
            ("rp-accord", "accord_holder"),
            ("rp-substrate", "substrate_persist"),
        ] {
            // v62.0.0 (E5) — an edition-2 `key:record` (hardware evidence is not
            // carried by the fixture record).
            put_e2_key(&backend, k, it).await;
        }
        // Build a minimal row with a given type + attesting/attested keys.
        // (The gate reads only attestation_type + attesting/attested key_id.)
        let row = |attn: &str, attesting: &str, attested: &str| {
            let mut a = fix_attestation("rp-att", attesting, attested, attesting);
            a.attestation_type = attn.to_owned();
            // v37.0.0 (CIRISPersist#733) — the accord legs assert the
            // EMITTER-CLASS rule, so their rows must be otherwise well-formed:
            // an `accord:*` row that names no accord is refused by
            // `check_accord_root_binding` first, and this witness would then be
            // measuring a neighbouring gate rather than CC 3.4.1.
            if attn.starts_with("accord:") {
                a.attestation_envelope["accord_root"] = serde_json::json!("rp-accord-root");
            }
            crate::federation::tier_ingest::test_support::reseal(&mut a);
            a
        };

        // accord:* — agent REJECTED (CC 3.4.1), accord_holder OK.
        let e = check_reserved_prefix_admission(
            &backend,
            &row("accord:invoke:notify:x", "rp-agent", "rp-agent"),
        )
        .await
        .unwrap_err();
        assert_eq!(
            e.kind(),
            "federation_accord_dimension_requires_accord_holder"
        );
        // E5-fix2 (round 6) — the "an `accord_holder` key may emit accord:*"
        // leg is DELETED (ruling 4): under edition 2 accord standing is held at
        // the named accord root (`edition2::standing::holds_accord_standing`,
        // CC 3.4.1), never an identity-type claim on a key record, so the leg
        // asserted the earlier form. The agent refusal above stands.

        // capacity:* — self-emission REJECTED (CC 3.4.5); non-self OK (any id).
        let e = check_reserved_prefix_admission(
            &backend,
            &row("capacity:composite", "rp-agent", "rp-agent"),
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "federation_capacity_self_emission_rejected");
        check_reserved_prefix_admission(
            &backend,
            &row("capacity:composite", "rp-agent", "rp-accord"),
        )
        .await
        .expect("non-self capacity:* is allowed");

        // system:* — agent REJECTED (CC 3.4.3), substrate_persist OK.
        let e = check_reserved_prefix_admission(
            &backend,
            &row("system:audit_chain:hash_continuity", "rp-agent", "rp-agent"),
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "federation_reserved_prefix_emitter_mismatch");
        check_reserved_prefix_admission(
            &backend,
            &row(
                "system:audit_chain:hash_continuity",
                "rp-substrate",
                "rp-substrate",
            ),
        )
        .await
        .expect("substrate_persist may emit system:*");

        // hard_case:* — agent REJECTED, substrate_persist OK.
        let e = check_reserved_prefix_admission(
            &backend,
            &row("hard_case:promotion_overdue", "rp-agent", "rp-agent"),
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "federation_reserved_prefix_emitter_mismatch");
        check_reserved_prefix_admission(
            &backend,
            &row(
                "hard_case:promotion_overdue",
                "rp-substrate",
                "rp-substrate",
            ),
        )
        .await
        .expect("substrate_persist may emit hard_case:*");

        // Non-reserved types fast-exit OK regardless of identity_type.
        check_reserved_prefix_admission(&backend, &row("scores", "rp-agent", "rp-agent"))
            .await
            .expect("scores is not a reserved type");
        check_reserved_prefix_admission(&backend, &row("delegates_to", "rp-agent", "rp-accord"))
            .await
            .expect("delegates_to is not a reserved type");

        // #307 (CC 3.4.11) — the age_self_declared:level:* refusal lives on
        // the attestation_TYPE gate (the REAL emit path), not just the
        // dimension gate. age tokens travel as the attestation_type string.
        for at in ["age_self_declared:level:adult", "age_self_declared:level"] {
            let e = check_reserved_prefix_admission(&backend, &row(at, "rp-agent", "rp-agent"))
                .await
                .expect_err("age_self_declared:level:* must be refused on the type gate");
            assert_eq!(
                e.kind(),
                "federation_dimension_rejected",
                "{at:?} should refuse with DimensionRejected",
            );
            match e {
                crate::federation::Error::DimensionRejected { reason, .. } => assert_eq!(
                    reason,
                    crate::federation::admission::DimensionRejectionReason::SelfDeclaredLevelReserved
                        .as_str(),
                ),
                other => panic!("expected DimensionRejected, got {other:?}"),
            }
        }
        // The `{band}` self rung still admits; a witness `age_assurance:*`
        // token also fast-exits this gate (its emitter rule is identity-gated
        // and not exercised here for an unregistered attester — use a
        // registered witness-free shape that simply isn't level-reserved).
        check_reserved_prefix_admission(
            &backend,
            &row("age_self_declared:band:adult", "rp-agent", "rp-agent"),
        )
        .await
        .expect("age_self_declared:band:* is admitted (subject-signed self rung)");
    }

    /// v17.9.0 (CC#38 interim) — the envelope size cap fires FIRST at both
    /// write chokepoint families: the federation put and the local-tier
    /// funnel. One backend suffices — the check is the single-sourced
    /// `check_envelope_size_admission` at every site (unit-pinned boundary
    /// in `federation::admission::envelope_size_tests`).
    #[tokio::test]
    async fn envelope_size_cap_refuses_oversize_at_both_write_paths() {
        use crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES;
        let backend = test_backend();
        let oversize = serde_json::json!({
            "d": "x".repeat(MAX_ATTESTATION_ENVELOPE_BYTES),
            // v62.0.0 (E0 fix 2) — registered (`test:` is open vocabulary).
            "dimension": "truth_grounding:oversize:v1",
        });

        // Federation put: refused before signature/directory work.
        let mut row = fix_attestation("cap-fed", "cap-k", "cap-k", "cap-k");
        row.attestation_envelope = oversize.clone();
        crate::federation::tier_ingest::test_support::reseal(&mut row);
        let err = NotLanded::of(
            &backend,
            put_voiced(&backend, &row).await,
            "oversize federation put must refuse",
        )
        .await;
        assert_eq!(err.kind(), "federation_envelope_too_large");

        // Local-tier funnel: refused at entry (no key seeding needed —
        // the cap fires before any lookup).
        let input = crate::federation::types::LocalAttestationInput {
            attestation_id: None,
            attesting_key_id: "cap-k".into(),
            attested_key_id: None,
            attestation_type: "scores".into(),
            attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(oversize)
                .unwrap(),
            subject_key_ids: Vec::new(),
            expires_at: None,
            weight: None,
            cohort_scope: "self".into(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        };
        let err = backend
            .attestation_upsert_local(input)
            .await
            .expect_err("oversize local upsert must refuse");
        assert_eq!(err.kind(), "federation_envelope_too_large");
    }

    // ── v11.5.0 (CIRISPersist#306, CC 3.2 / CC 3.3.12 / CC 1.15.6) ──────────
    //    I1 age band + user-target steward-binding gate + minor liveness.

    /// v30.3.0 (CIRISPersist#611) — **no node identity is an ERROR, not an
    /// empty chain.**
    ///
    /// The actual decision in #611. The fail-secure reflex on a read door is to
    /// return nothing, and it is wrong here: a host that forgot
    /// `set_node_key_id()` would watch legitimate vouches vanish with nothing
    /// in the result distinguishing "this content has no vouches" from "this
    /// node cannot check vouches". Those are different facts and a caller acts
    /// differently on each.
    ///
    /// One leg, not three: the code path is the shared `FederationDirectory`
    /// DEFAULT method, identical for every backend, and the conferral property
    /// itself is what carries the three-backend witness above.
    #[tokio::test]
    async fn publisher_vouch_without_node_identity_is_loud_611() {
        use crate::federation::FederationDirectory;
        let backend = test_backend();
        // Deliberately NOT calling set_node_key_id.
        let err = backend
            .lookup_trusted_publisher_chain(&"a".repeat(64))
            .await
            .expect_err("a directory that cannot check vouches must say so, not return none");
        assert_eq!(
            err.kind(),
            "federation_node_identity_unset",
            "must be the typed refusal (#565: the refusal names its branch), got: {err}"
        );
        assert!(
            err.to_string().contains("set_node_key_id"),
            "the message must name what to call, or it is not actionable: {err}"
        );
    }

    /// v30.2.0 (CIRISPersist#607) — **a self-asserted witness is REFUSED.**
    ///
    /// The whole of #607 in one assertion. Before this, any stranger could
    /// register with `identity_type: "witness"` and then assert an
    /// age-assurance LEVEL about a third party — the rung CC 3.4.11 reserves to
    /// a witness *precisely because a subject must not reach it*. The door
    /// membership-tested a string the stranger wrote themselves.
    ///
    /// The POSITIVE control is `put_conferred_key`, used by every other witness
    /// fixture here: same claim, same door, plus a conferral — admitted. Both
    /// halves are needed. Without the positive, "refuse everything" passes;
    /// without this, "admit everything" passes.
    #[tokio::test]
    async fn a_self_asserted_witness_is_refused_607() {
        let backend = test_backend();
        backend.set_node_key_id("sa-node");
        // The claim, with NO conferral behind it — the #607 attack exactly.
        put_typed_key(&backend, "sa-witness", "witness").await;
        put_typed_key(&backend, "sa-subject", "user").await;

        let att = fix_age_attestation(
            "sa-1",
            "sa-witness",
            "sa-subject",
            "age_assurance:government:adult:v1",
        );
        let err = NotLanded::of(
            &backend,
            put_voiced(&backend, &att).await,
            "a self-asserted witness must NOT be able to assert an age rung about a \
                 third party — that is CIRISPersist#607",
        )
        .await;
        let msg = err.to_string();
        assert!(
            msg.contains("infra:attest_assurance"),
            "the refusal must name the missing conferral so an operator knows what to obtain; \
             got: {msg}"
        );
    }

    /// v30.2.0 (CIRISPersist#607) — seed a key AND the trust-root conferral its
    /// reserved-prefix rule now resolves.
    ///
    /// A `witness` / `lenscore_detector` claim is no longer self-sufficient: the
    /// door asks whether a root THIS NODE trusts conferred the matching scope.
    /// This helper builds the honest path — a root, this node's `trust:accepts`
    /// edge to it, and the root's `trust:confers` edge carrying `scope` — so a
    /// fixture proves the gate ADMITS a properly conferred emitter, not merely
    /// that it refuses everything.
    ///
    /// The negative case (claim present, conferral absent) is
    /// `a_self_asserted_witness_is_refused_607`.
    async fn put_conferred_key(backend: &SqliteBackend, key_id: &str, it: &str, scope: &str) {
        // E5-fix2 (round 6; CP2) — PORTED to an edition-2 trust root. The
        // earlier fixture chartered a KEY root (`n607-root`) by hand; under
        // edition 2 a key-arm root is as attested as its holder's custody
        // evidence (CC 4.2.2.1, `trust_root::holder_hardware`), which no
        // fixture key can carry, so that root never validated and every
        // conferral it made rooted nowhere. The shared rooted root (W1:
        // founded by the bundle's holders, chartered, accepted by THIS node)
        // confers `scope` on `key_id` with the subject's own voice
        // (`put_conferral`). The reserved-prefix rule is satisfied by that
        // delegation ALONE; the signer's identity type is not read for it
        // (`admission::check_reserved_prefix_admission`), so `put_conferral`'s
        // `user` record stands in for `it`.
        let _ = it;
        if crate::federation::FederationDirectory::node_key_id(backend).is_none() {
            let node = e2::put_key(backend, "n607-node", &["node"]).await;
            backend.set_node_key_id(node);
        }
        let r = e2::rooted_trust_root(
            backend,
            &crate::federation::edition2::fixture_genesis::HOLDER_SEEDS,
            "quorum:2/3",
        )
        .await;
        crate::federation::edition2::fixture_trust_root::put_conferral(
            backend,
            &r,
            key_id,
            &[scope],
        )
        .await
        .unwrap_or_else(|e| panic!("the root confers {scope} on {key_id}: {e}"));
        // RT-fix1 — the postcondition (the K2-fix13 pattern): the grant
        // reaches the root through THIS node, so a conferral that confers
        // nothing stops here and not at a later band / row assert.
        let node = crate::federation::FederationDirectory::node_key_id(backend)
            .expect("put_conferred_key: the node key is set above");
        let rooted = crate::federation::trust_root::capability_roots_to_trusted_root(
            backend,
            &node,
            &e2::kid(key_id),
            scope,
            crate::host::clock::now(),
        )
        .await
        .expect("put_conferred_key: capability_roots_to_trusted_root");
        assert!(
            rooted.as_ref().is_some_and(|g| g.root_key_id == r.lineage),
            "put_conferred_key: {key_id}'s {scope} roots at {} through node {node}: {rooted:?}",
            r.lineage
        );
    }

    /// Register a key with a chosen `identity_type` (e.g. `user` / `witness` /
    /// `agent` / `node`).
    ///
    /// v62.0.0 (JSON cut, E5) — an edition-2 `key:record`; the key is then
    /// named by `e2::kid(key_id)`.
    async fn put_typed_key(backend: &SqliteBackend, key_id: &str, it: &str) {
        put_e2_key(backend, key_id, it).await;
    }

    /// Build a live age attestation ABOUT `subject` (attested_key_id ==
    /// subject) from `emitter`, carrying the given age `attestation_type`
    /// token + empty envelope. Properly hybrid-signed (CC 5.3.2.4.3.1).
    fn fix_age_attestation(id: &str, emitter: &str, subject: &str, token: &str) -> Attestation {
        let mut a = fix_attestation(id, emitter, subject, emitter);
        a.attestation_type = token.to_owned();
        a.attestation_envelope = serde_json::json!({ "id": id });
        a.expires_at = None;
        resign_fix(&mut a);
        a
    }

    /// age_band resolution: a self-declared minor LOWERS a witness adult
    /// (v62.0.0 K2-fix14, CC 3.4.11 read-union); self minor
    /// alone → Minor; self adult alone → Unknown (ratchet ignores self-adult);
    /// witness minor → Minor; no attestation → Unknown; expired witness
    /// attestation ignored.
    #[tokio::test]
    async fn age_band_resolution_witness_outranks_self_and_ratchets() {
        use crate::federation::age::{age_band, AgeBand};
        let backend = test_backend();
        put_conferred_key(
            &backend,
            "ab-witness",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "ab-subj", "user").await;

        // No attestation → Unknown (presumption of sovereignty).
        assert_eq!(
            age_band(&backend, &e2::kid("ab-subj")).await.unwrap(),
            AgeBand::Unknown
        );

        // Self-declared adult alone → Unknown (the one-way ratchet ignores a
        // self-declared adult).
        put_voiced(
            &backend,
            &fix_age_attestation(
                "ab-self-adult",
                "ab-subj",
                "ab-subj",
                "age_self_declared:band:adult",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            age_band(&backend, &e2::kid("ab-subj")).await.unwrap(),
            AgeBand::Unknown,
            "a self-declared adult must NOT graduate the subject to Adult",
        );

        // Add a self-declared MINOR → Minor (a subject may ratchet DOWN).
        // v62.0.0 (K2-fix20; CC 3.5.1 rule 3) — dated one minute after the
        // self-declared adult, so it is the subject's NEWEST row by instant
        // (a same-instant tie now goes to the lowest attestation_id, which
        // this test must not depend on).
        let mut self_minor = fix_age_attestation(
            "ab-self-minor",
            "ab-subj",
            "ab-subj",
            "age_self_declared:band:minor",
        );
        self_minor.asserted_at += chrono::Duration::minutes(1);
        self_minor.scrub_timestamp = self_minor.asserted_at;
        resign_fix(&mut self_minor);
        put_voiced(&backend, &self_minor).await.unwrap();
        assert_eq!(
            age_band(&backend, &e2::kid("ab-subj")).await.unwrap(),
            AgeBand::Minor
        );

        // v62.0.0 (K2-fix14; CC 3.4.11: "a subject's declaration of a lower
        // band lowers the reading and never raises it") — a witness ADULT
        // does not lift the subject's own self-declared minor → Minor.
        put_voiced(
            &backend,
            &fix_age_attestation(
                "ab-witness-adult",
                "ab-witness",
                "ab-subj",
                "age_assurance:provider:adult:v1",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            age_band(&backend, &e2::kid("ab-subj")).await.unwrap(),
            AgeBand::Minor,
            "a self-declared minor lowers the witness reading (CC 3.4.11)",
        );
    }

    /// age_band: a witness MINOR resolves Minor; an EXPIRED witness adult is
    /// ignored (liveness = expires_at only).
    #[tokio::test]
    async fn age_band_witness_minor_and_expired_witness_ignored() {
        use crate::federation::age::{age_band, AgeBand};
        let backend = test_backend();
        put_conferred_key(
            &backend,
            "abe-witness",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "abe-subj", "user").await;

        // Witness minor → Minor.
        put_voiced(
            &backend,
            &fix_age_attestation(
                "abe-w-minor",
                "abe-witness",
                "abe-subj",
                "age_assurance:provider:minor:v1",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            age_band(&backend, &e2::kid("abe-subj")).await.unwrap(),
            AgeBand::Minor
        );

        // An EXPIRED witness adult is ignored — Minor still wins (it is live).
        let mut expired = fix_age_attestation(
            "abe-w-adult-exp",
            "abe-witness",
            "abe-subj",
            "age_assurance:provider:adult:v1",
        );
        expired.expires_at = Some("2020-01-01T00:00:00Z".parse().unwrap());
        // v62.0.0 (K2-fix20; CC 3.5.1 rule 3) — dated one minute BEFORE the
        // witness's minor, so the minor is this witness's newest row by
        // instant (a same-instant tie now goes to the lowest attestation_id,
        // which this test must not depend on). An expired NEWEST row would
        // leave the witness no current row at all (K2-fix15).
        expired.asserted_at -= chrono::Duration::minutes(1);
        expired.scrub_timestamp = expired.asserted_at;
        resign_fix(&mut expired);
        put_voiced(&backend, &expired).await.unwrap();
        assert_eq!(
            age_band(&backend, &e2::kid("abe-subj")).await.unwrap(),
            AgeBand::Minor,
            "an expired witness adult must be ignored (liveness = expires_at)",
        );
    }

    /// CC 3.2 user-target gate decision table, exercised through the REAL
    /// `put_attestation` admission path.
    #[tokio::test]
    async fn user_target_steward_binding_gate_decision_table() {
        use crate::federation::types::delegation_scope as ds;
        let backend = test_backend();
        // S = adult-user steward; the witness that attests adulthood.
        put_conferred_key(
            &backend,
            "ut-witness",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "ut-S", "user").await;
        // Adult target A (witness-attested adult), unknown-age user U,
        // minor target M (witness-attested minor), node N.
        put_typed_key(&backend, "ut-A", "user").await;
        put_typed_key(&backend, "ut-U", "user").await;
        put_typed_key(&backend, "ut-M", "user").await;
        put_typed_key(&backend, "ut-N", "node").await;

        // Witness-attest S and A as adults; M as a minor.
        for (id, subj, token) in [
            ("uw-S", "ut-S", "age_assurance:provider:adult:v1"),
            ("uw-A", "ut-A", "age_assurance:provider:adult:v1"),
            ("uw-M", "ut-M", "age_assurance:provider:minor:v1"),
        ] {
            put_voiced(
                &backend,
                &fix_age_attestation(id, "ut-witness", subj, token),
            )
            .await
            .unwrap();
        }

        let deleg = |id: &str, s: &str, t: &str| {
            fix_owner_binding_delegates_to(id, s, t, s, &[ds::INFRA_SERVE])
        };

        // S(adult user) → A(adult user) : REJECTED (target_is_self_sovereign).
        let e = NotLanded::of(
            &backend,
            put_voiced(&backend, &deleg("utd-A", "ut-S", "ut-A")).await,
            "the row does not land",
        )
        .await;
        assert_eq!(e.kind(), "federation_user_target_steward_binding_forbidden");
        assert!(e.reason_is("target_is_self_sovereign"), "{e:?}");

        // S(adult) → U(no age = Unknown) : REJECTED (target_age_unverified).
        let e = NotLanded::of(
            &backend,
            put_voiced(&backend, &deleg("utd-U", "ut-S", "ut-U")).await,
            "the row does not land",
        )
        .await;
        assert!(e.reason_is("target_age_unverified"), "{e:?}");

        // S(adult user) → M(witness minor) : ADMITTED (legal guardianship).
        put_voiced(&backend, &deleg("utd-M", "ut-S", "ut-M"))
            .await
            .expect("adult-user steward → witness-minor ward is admitted");
        // (The granter-not-adult-user leg + node-target no-op are covered by
        // `user_target_gate_granter_must_be_adult_and_nodes_unaffected`.)
    }

    /// CC 3.2 user-target gate: a non-adult (Unknown-age) granter cannot
    /// steward even a proven minor (granter_not_adult_user); a node/agent
    /// target is unaffected by this gate (goes through node-agency only).
    #[tokio::test]
    async fn user_target_gate_granter_must_be_adult_and_nodes_unaffected() {
        use crate::federation::types::delegation_scope as ds;
        let backend = test_backend();
        put_conferred_key(
            &backend,
            "ug-witness",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "ug-U", "user").await; // unknown-age user (granter)
        put_typed_key(&backend, "ug-M", "user").await; // witness-minor ward
        put_typed_key(&backend, "ug-N", "node").await; // node target

        put_voiced(
            &backend,
            &fix_age_attestation(
                "ugw-M",
                "ug-witness",
                "ug-M",
                "age_assurance:provider:minor:v1",
            ),
        )
        .await
        .unwrap();

        // U(unknown-age user) → M(minor) : REJECTED (granter not proven adult).
        let e = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_owner_binding_delegates_to(
                    "ugd-UM",
                    "ug-U",
                    "ug-M",
                    "ug-U",
                    &[ds::INFRA_SERVE],
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert!(e.reason_is("granter_not_adult_user"), "{e:?}");

        // U(unknown-age user) → N(node) : the user-target gate is a no-op for a
        // node target (infra:* scope clears the node-agency gate) → ADMITTED.
        put_voiced(
            &backend,
            &fix_owner_binding_delegates_to("ugd-UN", "ug-U", "ug-N", "ug-U", &[ds::INFRA_SERVE]),
        )
        .await
        .expect("a node target is governed by the node-agency gate, not the user-target gate");
    }

    // ── v13.0.0 (CIRISPersist#368, CC 3.4.11 / CC 3.4.13) ────────────────
    //    Witness-targets-subject age_assurance admission decision table.

    /// CC 3.4.11 witness-targets-subject decision table, through the REAL
    /// `put_attestation` admission path:
    ///
    /// - a witness emitting `age_assurance:*` ABOUT a DIFFERENT subject is
    ///   ADMITTED and graduates THAT subject's band (witness outranks the
    ///   subject's own self-declared rung);
    /// - a witness emitting `age_assurance:*` about ITSELF (attester ==
    ///   attested) is REJECTED — "a subject MUST NOT emit on
    ///   `age_assurance:`" — so nobody self-mints their own graduation;
    /// - a non-witness cross-subject emitter is still REJECTED by the
    ///   unchanged identity gate (reserved-prefix emitter mismatch).
    #[tokio::test]
    async fn age_assurance_witness_targets_subject_decision_table() {
        use crate::federation::age::{age_band, age_band_fine, AgeBand, AgeBandFine};
        let backend = test_backend();
        put_conferred_key(
            &backend,
            "wts-witness",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "wts-T", "user").await; // the subject
        put_typed_key(&backend, "wts-P", "user").await; // plain (non-witness) user

        // Baseline: T self-declares ADULT (the non-reserved self rung still
        // admits attester==attested — it is subject-signed by design), which
        // graduates nobody. v62.0.0 (K2-fix14): the baseline was a
        // self-declared MINOR, but under CC 3.4.11 a subject's own minor
        // band lowers any witness reading, so it would hide the graduation
        // this table witnesses.
        put_voiced(
            &backend,
            &fix_age_attestation(
                "wts-self-adult",
                "wts-T",
                "wts-T",
                "age_self_declared:band:adult:v1",
            ),
        )
        .await
        .expect("subject-signed self rung admits");
        assert_eq!(
            age_band(&backend, &e2::kid("wts-T")).await.unwrap(),
            AgeBand::Unknown
        );

        // CROSS-SUBJECT witness graduation: W attests T adult — ADMITTED, and
        // T's band graduates (a self-declared adult raises nothing; the witness
        // does).
        put_voiced(
            &backend,
            &fix_age_attestation(
                "wts-w-adult",
                "wts-witness",
                "wts-T",
                "age_assurance:government:adult:v1",
            ),
        )
        .await
        .expect("witness-targets-subject age_assurance is admitted (CC 3.4.13)");
        assert_eq!(
            age_band(&backend, &e2::kid("wts-T")).await.unwrap(),
            AgeBand::Adult,
            "a witness row ABOUT T graduates T's band",
        );
        assert_eq!(
            age_band_fine(&backend, &e2::kid("wts-T")).await.unwrap(),
            AgeBandFine::Adult,
            "the finer resolution graduates too",
        );

        // SELF-graduation via the witness prefix: W attests W — REJECTED
        // (attester == attested; CC 3.4.11 "a subject MUST NOT emit on
        // `age_assurance:`"). The witness identity_type does NOT bypass.
        let e = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_age_attestation(
                    "wts-w-self",
                    "wts-witness",
                    "wts-witness",
                    "age_assurance:provider:adult:v1",
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_eq!(e.kind(), "federation_age_assurance_self_emission_rejected");
        assert_eq!(
            age_band(&backend, &e2::kid("wts-witness")).await.unwrap(),
            AgeBand::Unknown,
            "the rejected self-emission confers nothing",
        );

        // Identity gate UNCHANGED: a plain user cross-attesting T's age is
        // still refused (reserved prefix requires a witness emitter).
        let e = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_age_attestation(
                    "wts-p-cross",
                    "wts-P",
                    "wts-T",
                    "age_assurance:provider:minor:v1",
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_eq!(e.kind(), "federation_reserved_prefix_emitter_mismatch");
    }

    /// #368 read-side defense-in-depth: a self-emitted `age_assurance:*` row
    /// that PRE-DATES the admission gate (or arrived via replication before
    /// v13.0.0) must not graduate its own emitter either. Injected directly
    /// into backend state (bypassing `put_attestation`) to simulate the
    /// legacy row; `age_band` / `age_band_fine` skip it.
    #[tokio::test]
    async fn age_band_ignores_pre_gate_self_emitted_witness_row() {
        use crate::federation::age::{age_band, age_band_fine, AgeBand, AgeBandFine};
        let backend = test_backend();
        put_conferred_key(
            &backend,
            "pg-witness",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "pg-T", "user").await;

        // Bypass the gate: push a self-emitted witness-adult row directly.
        let legacy = fix_age_attestation(
            "pg-self-adult",
            "pg-witness",
            "pg-witness",
            "age_assurance:government:adult:v1",
        );
        backend.plant_attestation_below_the_door(legacy);

        assert_eq!(
            age_band(&backend, &e2::kid("pg-witness")).await.unwrap(),
            AgeBand::Unknown,
            "a pre-gate self-emitted witness row is skipped at read time",
        );
        assert_eq!(
            age_band_fine(&backend, &e2::kid("pg-witness"))
                .await
                .unwrap(),
            AgeBandFine::Unknown,
        );

        // Control: the SAME token about a DIFFERENT subject resolves.
        let cross = fix_age_attestation(
            "pg-cross-adult",
            "pg-witness",
            "pg-T",
            "age_assurance:government:adult:v1",
        );
        backend.plant_attestation_below_the_door(cross);
        assert_eq!(
            age_band(&backend, &e2::kid("pg-T")).await.unwrap(),
            AgeBand::Adult
        );
    }

    // ── CIRISPersist#309 (CC 3.4.12) — adult-incapacity steward-binding ──

    /// Build an adult-incapacity `delegates_to(steward -> ward)` carrying the
    /// CC 3.4.12 envelope fields. `scope` = decision-domains; the optionals
    /// mirror `capacity::binding_field::*`.
    #[allow(clippy::too_many_arguments)]
    fn fix_incapacity_binding(
        id: &str,
        steward: &str,
        ward: &str,
        scope: &[&str],
        legit: Option<&str>,
        valid_until: Option<&str>,
        binding_tier: Option<&str>,
        petitioner: Option<&str>,
    ) -> Attestation {
        let mut att = fix_attestation(id, steward, ward, steward);
        att.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
        crate::federation::tier_ingest::test_support::reseal(&mut att);
        let mut env = serde_json::json!({
            "id": id,
            "scope": scope.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            // v30.8.0 (CIRISConstitution#87) — an incapacity binding is a CUSTODY
            // CLAIM by construction, so it declares itself as one. Since the
            // ruling, custody must be DECLARED: an undeclared `delegates_to` to a
            // person is a capability conferral. That matters most for the
            // `missing_legitimacy_source` case — a binding that omits its
            // justification is otherwise indistinguishable from a conferral, and
            // would slip past the gate that exists to punish exactly that
            // omission. Declaring custody is what makes the omission visible.
            //
            // Fail-safe either way: an undeclared edge confers no custody, so a
            // host that forgets the marker gets a grant that establishes nothing
            // rather than silent stewardship.
            "delegation_purpose": crate::federation::types::owner_binding::CC_DELEGATION_PURPOSE,
        });
        let obj = env.as_object_mut().unwrap();
        if let Some(l) = legit {
            obj.insert("binding_legitimacy_source".into(), serde_json::json!(l));
        }
        if let Some(v) = valid_until {
            obj.insert("valid_until".into(), serde_json::json!(v));
        }
        if let Some(t) = binding_tier {
            obj.insert("binding_tier".into(), serde_json::json!(t));
        }
        if let Some(p) = petitioner {
            obj.insert("petitioner_key_id".into(), serde_json::json!(p));
        }
        att.attestation_envelope = env;
        resign_fix(&mut att);
        att
    }

    fn assert_forbidden(e: &NotLanded, want: &str) {
        assert_eq!(e.kind(), "federation_user_target_steward_binding_forbidden");
        assert!(
            e.reason_is(want),
            "wrong rejection reason, want {want}: {e:?}"
        );
    }

    /// Register `assessor`(witness), `S`(adult user), `A`(adult user); attest
    /// S and A adults. Returns nothing; keys are `<p>-assessor/-S/-A`.
    async fn bootstrap_incapacity(backend: &SqliteBackend, p: &str) {
        // v30.2.0 (CIRISPersist#607) — the assessor is a witness, and a witness
        // now needs a trust-root conferral before `age_assurance:` admits.
        put_conferred_key(
            backend,
            &format!("{p}-assessor"),
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(backend, &format!("{p}-S"), "user").await;
        put_typed_key(backend, &format!("{p}-A"), "user").await;
        for who in ["S", "A"] {
            put_voiced(
                backend,
                &fix_age_attestation(
                    &format!("{p}w-{who}"),
                    &format!("{p}-assessor"),
                    &format!("{p}-{who}"),
                    "age_assurance:provider:adult:v1",
                ),
            )
            .await
            .unwrap();
        }
    }

    /// Put a capacity attestation ABOUT `ward` from `attester`.
    async fn put_capacity(
        backend: &SqliteBackend,
        id: &str,
        attester: &str,
        ward: &str,
        token: &str,
    ) {
        put_voiced(backend, &fix_age_attestation(id, attester, ward, token))
            .await
            .unwrap_or_else(|e| panic!("capacity attestation {token} rejected: {e:?}"));
    }

    /// CC 3.4.12 capacity-assurance emitter discipline: witness-RESERVED (a
    /// non-witness emitter is rejected) AND the subject MUST NOT self-emit
    /// (attester == attested rejected even for a witness).
    #[tokio::test]
    async fn capacity_assurance_witness_reserved_and_no_self_emit() {
        let backend = test_backend();
        put_conferred_key(
            &backend,
            "cap-assessor",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "cap-user", "user").await;
        put_typed_key(&backend, "cap-subj", "user").await;

        // A witness assessor CAN attest another's capacity.
        put_voiced(
            &backend,
            &fix_age_attestation(
                "cap-ok",
                "cap-assessor",
                "cap-subj",
                "capacity_assurance:panel:financial:incapacitated:v1",
            ),
        )
        .await
        .expect("witness assessor may attest another's capacity");

        // A non-witness (plain user) may NOT emit capacity_assurance.
        let e = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_age_attestation(
                    "cap-nonwit",
                    "cap-user",
                    "cap-subj",
                    "capacity_assurance:provider:medical:incapacitated:v1",
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_eq!(e.kind(), "federation_reserved_prefix_emitter_mismatch");

        // The SUBJECT must not self-mint their own (in)capacity, even as a
        // witness (attester == attested).
        put_conferred_key(
            &backend,
            "cap-selfwit",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        let e = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_age_attestation(
                    "cap-self",
                    "cap-selfwit",
                    "cap-selfwit",
                    "capacity_assurance:provider:financial:incapacitated:v1",
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_eq!(e.kind(), "federation_capacity_self_emission_rejected");
    }

    /// CC 3.4.12 adult-incapacity admission decision table (through the REAL
    /// `put_attestation` path): presumption-of-capacity, missing legitimacy /
    /// valid_until, cadence ceiling, scope containment, reversible exclusion,
    /// then a valid ADMIT that makes the steward a live anchor.
    #[tokio::test]
    async fn adult_incapacity_binding_gate_decision_table() {
        use crate::federation::admission::steward_bindings_of;
        use chrono::{Duration, Utc};
        let backend = test_backend();
        bootstrap_incapacity(&backend, "ai").await;
        let future =
            crate::federation::admission::render_signed_instant(Utc::now() + Duration::days(30));

        // (0) presumption of capacity — an adult with NO incapacity attested is
        // self-sovereign (the CC 3.2 un-stewardable default reasserts).
        let e = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_incapacity_binding(
                    "ai-0",
                    "ai-S",
                    "ai-A",
                    &["financial"],
                    Some("prior_will_proxy"),
                    Some(&future),
                    None,
                    None,
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_forbidden(&e, "target_is_self_sovereign");

        // Attest A incapacitated for `financial` + rule out reversible mimics.
        put_capacity(
            &backend,
            "aic-fin",
            "ai-assessor",
            "ai-A",
            "capacity_assurance:panel:financial:incapacitated:v1",
        )
        .await;
        put_capacity(
            &backend,
            "aic-fin-rex",
            "ai-assessor",
            "ai-A",
            "capacity_assurance:reversible_excluded:financial:v1",
        )
        .await;

        // (1) missing legitimacy source → naked self-appointment refused.
        let e = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_incapacity_binding(
                    "ai-1",
                    "ai-S",
                    "ai-A",
                    &["financial"],
                    None,
                    Some(&future),
                    None,
                    None,
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_forbidden(&e, "missing_legitimacy_source");

        // (2) missing valid_until → no fail-to-liberty expiry.
        let e = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_incapacity_binding(
                    "ai-2",
                    "ai-S",
                    "ai-A",
                    &["financial"],
                    Some("prior_will_proxy"),
                    None,
                    None,
                    None,
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_forbidden(&e, "missing_valid_until");

        // (3) valid_until beyond the T2 review cadence (90d) → rejected.
        let far =
            crate::federation::admission::render_signed_instant(Utc::now() + Duration::days(200));
        let e = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_incapacity_binding(
                    "ai-3",
                    "ai-S",
                    "ai-A",
                    &["financial"],
                    Some("prior_will_proxy"),
                    Some(&far),
                    None,
                    None,
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_forbidden(&e, "valid_until_exceeds_review_cadence");

        // (4) scope exceeds the attested-incapacitated domains.
        let e = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_incapacity_binding(
                    "ai-4",
                    "ai-S",
                    "ai-A",
                    &["medical"],
                    Some("prior_will_proxy"),
                    Some(&future),
                    None,
                    None,
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_forbidden(&e, "scope_exceeds_attested_domains");

        // (5) attested incapacitated but reversible mimics NOT excluded.
        put_capacity(
            &backend,
            "aic-res",
            "ai-assessor",
            "ai-A",
            "capacity_assurance:provider:residence:incapacitated:v1",
        )
        .await;
        let e = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_incapacity_binding(
                    "ai-5",
                    "ai-S",
                    "ai-A",
                    &["residence"],
                    Some("prior_will_proxy"),
                    Some(&future),
                    None,
                    None,
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_forbidden(&e, "capacity_reversible_not_excluded");

        // (6) ADMIT — scope ⊆ attested loss, reversible excluded, prior-will
        // legitimacy, bounded valid_until, independent assessor.
        put_voiced(
            &backend,
            &fix_incapacity_binding(
                "ai-6",
                "ai-S",
                "ai-A",
                &["financial"],
                Some("prior_will_proxy"),
                Some(&future),
                None,
                None,
            ),
        )
        .await
        .expect("valid adult-incapacity binding is admitted");

        // A live binding makes S an anchor of A; A (an adult) also self-anchors
        // (it is never demoted to a perpetual minor).
        let anchors = steward_bindings_of(&backend, &e2::kid("ai-A"))
            .await
            .unwrap();
        assert!(anchors.contains(&"ai-S".to_string()), "S is a live anchor");
        assert!(
            anchors.contains(&"ai-A".to_string()),
            "the adult retains its own self-anchor (never a perpetual minor)"
        );
    }

    /// CC 3.4.12 T1 acute path: `reversible_pending` (in lieu of `_excluded`)
    /// is admissible ONLY for `binding_tier == T1_emergency_necessity` with the
    /// `emergency_necessity_expedited` legitimacy source.
    #[tokio::test]
    async fn adult_incapacity_t1_reversible_pending_path() {
        use crate::federation::capacity::{legitimacy_source, tier};
        use chrono::{Duration, Utc};
        let backend = test_backend();
        bootstrap_incapacity(&backend, "t1").await;
        let soon =
            crate::federation::admission::render_signed_instant(Utc::now() + Duration::days(2));
        put_capacity(
            &backend,
            "t1c",
            "t1-assessor",
            "t1-A",
            "capacity_assurance:provider:medical:incapacitated:v1",
        )
        .await;
        put_capacity(
            &backend,
            "t1c-pend",
            "t1-assessor",
            "t1-A",
            "capacity_assurance:reversible_pending:medical:v1",
        )
        .await;

        // Standard path (no T1 tier) with only `pending` → rejected.
        let e = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_incapacity_binding(
                    "t1-std",
                    "t1-S",
                    "t1-A",
                    &["medical"],
                    Some(legitimacy_source::PRIOR_WILL_PROXY),
                    Some(&soon),
                    None,
                    None,
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_forbidden(&e, "capacity_reversible_not_excluded");

        // T1 acute path → admitted.
        put_voiced(
            &backend,
            &fix_incapacity_binding(
                "t1-ok",
                "t1-S",
                "t1-A",
                &["medical"],
                Some(legitimacy_source::EMERGENCY_NECESSITY_EXPEDITED),
                Some(&soon),
                Some(tier::T1_EMERGENCY_NECESSITY),
                None,
            ),
        )
        .await
        .expect("T1 emergency-necessity + reversible_pending is admitted");
    }

    /// CC 3.4.12 apophatic floor: a protected non-transferable domain (voting)
    /// is rejected even when incapacity + reversible exclusion are attested.
    #[tokio::test]
    async fn adult_incapacity_protected_domain_rejected() {
        use chrono::{Duration, Utc};
        let backend = test_backend();
        bootstrap_incapacity(&backend, "pd").await;
        let future =
            crate::federation::admission::render_signed_instant(Utc::now() + Duration::days(10));
        put_capacity(
            &backend,
            "pdc",
            "pd-assessor",
            "pd-A",
            "capacity_assurance:panel:voting:incapacitated:v1",
        )
        .await;
        put_capacity(
            &backend,
            "pdc-rex",
            "pd-assessor",
            "pd-A",
            "capacity_assurance:reversible_excluded:voting:v1",
        )
        .await;
        let e = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_incapacity_binding(
                    "pd-b",
                    "pd-S",
                    "pd-A",
                    &["voting"],
                    Some("wa_due_process_quorum"),
                    Some(&future),
                    None,
                    None,
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_forbidden(&e, "scope_touches_protected_domain");
    }

    /// CC 3.4.12 assessor-independence: the capacity attester may not be the
    /// petitioner (anti-capture). The steward-is-attester case rides the same
    /// `incapacity_attesters.contains(steward)` branch.
    #[tokio::test]
    async fn adult_incapacity_conflicted_attester_rejected() {
        use chrono::{Duration, Utc};
        let backend = test_backend();
        bootstrap_incapacity(&backend, "cf").await;
        let future =
            crate::federation::admission::render_signed_instant(Utc::now() + Duration::days(10));
        put_capacity(
            &backend,
            "cfc",
            "cf-assessor",
            "cf-A",
            "capacity_assurance:panel:financial:incapacitated:v1",
        )
        .await;
        put_capacity(
            &backend,
            "cfc-rex",
            "cf-assessor",
            "cf-A",
            "capacity_assurance:reversible_excluded:financial:v1",
        )
        .await;
        // petitioner == the assessor → conflicted.
        let e = NotLanded::of(
            &backend,
            put_voiced(
                &backend,
                &fix_incapacity_binding(
                    "cf-b",
                    "cf-S",
                    "cf-A",
                    &["financial"],
                    Some("wa_due_process_quorum"),
                    Some(&future),
                    None,
                    Some("cf-assessor"),
                ),
            )
            .await,
            "the row does not land",
        )
        .await;
        assert_forbidden(&e, "attester_conflicted");
    }

    /// Minor-stewardship liveness fail-secure (CC 3.2): a minor user bound by
    /// an adult (live edge) is steward-bound; after the granter withdraws it,
    /// is_steward_bound flips to false (the minor does NOT self-anchor). A
    /// node is unchanged; an adult user self-anchors with no edge.
    #[tokio::test]
    async fn minor_stewardship_liveness_fails_secure_nodes_and_adults_unchanged() {
        use crate::federation::admission::{is_steward_bound, steward_bindings_of};
        use crate::federation::types::delegation_scope as ds;
        let backend = test_backend();
        put_conferred_key(
            &backend,
            "ml-witness",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "ml-S", "user").await; // adult-user steward
        put_typed_key(&backend, "ml-M", "user").await; // minor-user ward
        put_typed_key(&backend, "ml-A", "user").await; // adult-user (self-sovereign)
        put_typed_key(&backend, "ml-N", "node").await; // node control

        // Attest S and A as adults, M as a minor.
        for (id, subj, token) in [
            ("mlw-S", "ml-S", "age_assurance:provider:adult:v1"),
            ("mlw-A", "ml-A", "age_assurance:provider:adult:v1"),
            ("mlw-M", "ml-M", "age_assurance:provider:minor:v1"),
        ] {
            put_voiced(
                &backend,
                &fix_age_attestation(id, "ml-witness", subj, token),
            )
            .await
            .unwrap();
        }

        // An adult user with no edge self-anchors (sovereign — its own steward).
        assert!(
            is_steward_bound(&backend, &e2::kid("ml-A")).await.unwrap(),
            "an adult user is its own steward anchor",
        );

        // A steward-less minor does NOT self-anchor (fail-secure).
        assert!(
            !is_steward_bound(&backend, &e2::kid("ml-M")).await.unwrap(),
            "a steward-less minor must NOT self-anchor (CC 3.2 fail-secure)",
        );

        // Bind the minor to the adult steward (live edge) → steward-bound.
        put_voiced(
            &backend,
            &fix_owner_binding_delegates_to("ml-bind", "ml-S", "ml-M", "ml-S", &[ds::INFRA_SERVE]),
        )
        .await
        .expect("adult-user steward → minor ward admitted");
        assert!(is_steward_bound(&backend, &e2::kid("ml-M")).await.unwrap());
        assert_eq!(
            steward_bindings_of(&backend, &e2::kid("ml-M"))
                .await
                .unwrap(),
            vec!["ml-S".to_string()],
            "while bound, the minor is anchored only to the adult steward (NOT self)",
        );

        // The adult withdraws the binding → the minor fails secure again.
        let mut w = fix_attestation("ml-withdraw", "ml-S", "ml-M", "ml-S");
        w.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.into();
        w.attestation_envelope = serde_json::json!({ "id": "ml-withdraw" });
        resign_fix(&mut w);
        put_voiced(&backend, &w).await.unwrap();
        assert!(
            !is_steward_bound(&backend, &e2::kid("ml-M")).await.unwrap(),
            "a minor whose only adult steward was withdrawn must be steward-less (fail-secure)",
        );
        assert!(steward_bindings_of(&backend, &e2::kid("ml-M"))
            .await
            .unwrap()
            .is_empty());

        // Control: a node bound then withdrawn is unchanged (bound→true,
        // withdrawn→false) — the node path never used clauses (1)/(2).
        put_voiced(
            &backend,
            &fix_owner_binding_delegates_to("ml-nbind", "ml-S", "ml-N", "ml-S", &[ds::INFRA_SERVE]),
        )
        .await
        .unwrap();
        assert!(is_steward_bound(&backend, &e2::kid("ml-N")).await.unwrap());
        let mut wn = fix_attestation("ml-nwithdraw", "ml-S", "ml-N", "ml-S");
        wn.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.into();
        wn.attestation_envelope = serde_json::json!({ "id": "ml-nwithdraw" });
        resign_fix(&mut wn);
        put_voiced(&backend, &wn).await.unwrap();
        assert!(
            !is_steward_bound(&backend, &e2::kid("ml-N")).await.unwrap(),
            "the node/agent fail-secure path is unchanged by the minor gate",
        );
    }

    // ─── v62.0.0 (JSON cut, E5) — the #502 E1/E4 typed-object signature
    //     witnesses (revocation, family, community, the two membership
    //     revocations, location proof) are deleted: each checked a JSON
    //     typed object's hybrid signature over its JCS image against the
    //     authority it names. An edition-2 statement is checked at the door
    //     (the key-of-issuer check, `kid_not_of_iss`), witnessed by the
    //     edition-2 door invariants.
}
