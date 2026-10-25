//! v60.0.0 (CIRISPersist#1002) — **the retired memory backend's own tests,
//! on SQLite.**
//!
//! These are the tests `src/store/memory.rs` carried that had no SQL twin: each
//! ran on the in-memory map backend only. With that backend retired they run
//! on [`test_backend`](super::test_backend::test_backend), the migrated
//! in-memory SQLite. The memory-only duplicates (a body shared with a sqlite
//! and postgres leg, or an explicitly named `_sqlite` twin) were dropped, not
//! moved; the S5 handoff lists them.

#[cfg(test)]
mod accord_tests {
    #[allow(unused_imports)]
    use crate::schema::ReasoningEventType;
    #[allow(unused_imports)]
    use crate::store::backend::{Backend, InsertReport};
    #[allow(unused_imports)]
    use crate::store::sqlite::SqliteBackend;
    use crate::store::test_backend::test_backend;
    #[allow(unused_imports)]
    use crate::store::types::{TraceEventRow, TraceLlmCallRow};
    #[allow(unused_imports)]
    use crate::store::Error;
    #[allow(unused_imports)]
    use ed25519_dalek::VerifyingKey;
    #[allow(unused_imports)]
    use std::collections::{HashMap, HashSet};

    /// v22.0.0 (CIRISPersist#543) — the `scores` ENVELOPE-SCHEMA gate, which
    /// the memory backend did not have: no resolver field, no accessor, no
    /// call site. It was latent rather than live only because the default
    /// [`crate::federation::NoOpSchemaResolver`] answers `None` — a host that
    /// installed a REAL resolver got enforcement on sqlite + postgres and
    /// silence here.
    ///
    /// Written as a DIFFERENTIAL rather than two independent assertions: the
    /// same stub resolver and the same violating envelope go through both
    /// backends and the two `error_kind`s must be equal. That drives sqlite's
    /// answer instead of hard-coding a guess at it, which is what
    /// `assert_parity`'s hard `error_kind` equality now demands of every gate.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn envelope_schema_gate_matches_sqlite_sqlite_543() {
        use crate::federation::{
            AxisSchema, FederationDirectory as _, SchemaResolver, SchemaResolverError,
            SignedAttestation,
        };
        use crate::store::backend::Backend as _;

        /// Resolver that always yields a schema requiring `evidence_refs`.
        struct AlwaysRequiresEvidence;
        impl SchemaResolver for AlwaysRequiresEvidence {
            fn resolve<'a>(
                &'a self,
                _dimension: &'a str,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<Option<AxisSchema>, SchemaResolverError>,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async {
                    Ok(Some(AxisSchema {
                        sha256: [0u8; 32],
                        document: serde_json::json!({
                            "type": "object",
                            "required": ["evidence_refs"],
                        }),
                    }))
                })
            }
        }

        // A neutral dimension: `detection:*` and friends are reserved-prefix
        // gated to specific identity types, and a row that bounces off THAT
        // gate would prove nothing about this one. `trust:demo:v1` is the
        // dimension the shared AV-77 exercise already drives through every
        // other gate on all three backends.
        const DIM: &str = "trust:demo:v1";
        // `scores_row`'s envelope carries dimension/score/confidence and NO
        // `evidence_refs`, so it violates the schema above.
        let row = |id: &str| {
            crate::federation::bootstrap_admission::test_support::scores_row(
                id, "sch543", "sch543", DIM,
            )
        };

        // (a) DEFAULT resolver is still a no-op — nothing that passes today
        // starts failing. This is the half that protects every other test.
        let plain = test_backend();
        crate::federation::tier_ingest::test_support::register_hybrid_key(&plain, "sch543").await;
        plain
            .put_attestation(SignedAttestation {
                attestation: row(&uuid::Uuid::new_v4().to_string()),
            })
            .await
            .expect("the default NoOpSchemaResolver must leave the gate a no-op");

        // (b) THE DIFFERENTIAL — same resolver, same row, both backends.
        let mem = test_backend();
        crate::federation::tier_ingest::test_support::register_hybrid_key(&mem, "sch543").await;
        mem.set_schema_resolver(std::sync::Arc::new(AlwaysRequiresEvidence));
        let mem_err = mem
            .put_attestation(SignedAttestation {
                attestation: row(&uuid::Uuid::new_v4().to_string()),
            })
            .await
            .expect_err("memory must refuse an envelope that violates its axis schema");

        let sq = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .expect("open sqlite");
        sq.run_migrations().await.expect("migrations");
        crate::federation::tier_ingest::test_support::register_hybrid_key(&sq, "sch543").await;
        sq.set_schema_resolver(std::sync::Arc::new(AlwaysRequiresEvidence));
        let sq_err = sq
            .put_attestation(SignedAttestation {
                attestation: row(&uuid::Uuid::new_v4().to_string()),
            })
            .await
            .expect_err("sqlite refuses the same row");

        assert_eq!(
            mem_err.kind(),
            sq_err.kind(),
            "the two backends must refuse at the same gate KIND — a gate that refuses \
             correctly but reports differently is still a failing divergence under \
             `assert_parity` (memory {mem_err:?} vs sqlite {sq_err:?})"
        );
        // And the shared kind is the typed schema violation, not a generic backend error.
        assert!(
            matches!(
                &mem_err,
                crate::federation::Error::EnvelopeSchemaViolation { dimension, .. }
                    if dimension == DIM
            ),
            "and it names the violating dimension: {mem_err:?}"
        );
    }

    /// v31.0.0 (CIRISPersist#650) — THE MUTATION. Pure, so it runs on every
    /// backend leg: disable the fold (replay the interim states) and the
    /// withdrawn grant flips from `Purge` to `Restamp` — i.e. it is re-minted
    /// as a valid, freshly-signed, peer-admissible v31 row.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[test]
    fn the_v31_fold_is_load_bearing_650() {
        crate::federation::migration::test_support::assert_the_fold_is_load_bearing();
    }

    // ── freshness_floor (CIRISPersist#519 item 2a-iii) witnesses ────
}

#[cfg(test)]
mod tests {
    use crate::federation::membership_acceptance::test_support::ConsentedWidening as _;
    use crate::schema::CompleteTrace;
    #[allow(unused_imports)]
    use crate::schema::ReasoningEventType;
    use crate::schema::{ComponentType, SchemaVersion, TraceLevel};
    #[allow(unused_imports)]
    use crate::store::backend::{Backend, InsertReport};
    use crate::store::decompose::decompose;
    #[allow(unused_imports)]
    use crate::store::sqlite::SqliteBackend;
    use crate::store::test_backend::test_backend;
    #[allow(unused_imports)]
    use crate::store::types::{TraceEventRow, TraceLlmCallRow};
    #[allow(unused_imports)]
    use crate::store::Error;
    #[allow(unused_imports)]
    use ed25519_dalek::VerifyingKey;
    #[allow(unused_imports)]
    use std::collections::{HashMap, HashSet};

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

    #[tokio::test]
    async fn insert_returns_inserted_count() {
        let backend = test_backend();
        let rows = vec![
            fixture_row(0, ReasoningEventType::ThoughtStart),
            fixture_row(0, ReasoningEventType::ConscienceResult),
            fixture_row(1, ReasoningEventType::ConscienceResult),
        ];
        let report = backend.insert_trace_events_batch(&rows).await.unwrap();
        assert_eq!(report.inserted, 3);
        assert_eq!(report.conflicted, 0);
    }

    /// Mission category §4 "Idempotency": adapter retries must not
    /// double-insert. Re-submitting the same batch produces zero new
    /// rows and `conflicted == batch.len()`.
    #[tokio::test]
    async fn idempotent_on_dedup_key() {
        let backend = test_backend();
        let rows = vec![
            fixture_row(0, ReasoningEventType::ThoughtStart),
            fixture_row(0, ReasoningEventType::ActionResult),
        ];
        let r1 = backend.insert_trace_events_batch(&rows).await.unwrap();
        assert_eq!(r1.inserted, 2);
        let r2 = backend.insert_trace_events_batch(&rows).await.unwrap();
        assert_eq!(r2.inserted, 0);
        assert_eq!(r2.conflicted, 2);
        // Same total count after second insert.
        assert_eq!(backend.snapshot_events().len(), 2);
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

    /// v13.0.0 (CIRISPersist#365, CC 3.4.7.2) — consent_role round-trip,
    /// OQ-1 overwrite-on-revoke via set_consent_role, and the
    /// consent_role_of resolver, on the memory backend.
    #[tokio::test]
    async fn consent_role_round_trip_overwrite_and_resolver_sqlite() {
        use crate::federation::consent::consent_role_of;
        use crate::federation::types::consent_role;
        let backend = test_backend();

        // Born with consent_role = peer → round-trips through put/lookup.
        let mut key = fix_key("k-cr", "primitive-cr", "k-cr");
        key.consent_role = Some(consent_role::PEER.into());
        crate::federation::FederationDirectory::put_public_key(
            &backend,
            crate::federation::SignedKeyRecord { record: key },
        )
        .await
        .unwrap();
        let got = crate::federation::FederationDirectory::lookup_public_key(&backend, "k-cr")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.consent_role.as_deref(), Some(consent_role::PEER));
        assert_eq!(
            consent_role_of(&backend, "k-cr").await.unwrap().as_deref(),
            Some(consent_role::PEER)
        );

        // OQ-1 overwrite → authorized_review (flat, non-recursive).
        crate::federation::FederationDirectory::set_consent_role(
            &backend,
            "k-cr",
            Some(consent_role::AUTHORIZED_REVIEW),
        )
        .await
        .unwrap();
        assert_eq!(
            consent_role_of(&backend, "k-cr").await.unwrap().as_deref(),
            Some(consent_role::AUTHORIZED_REVIEW)
        );

        // Revoke (overwrite to None).
        crate::federation::FederationDirectory::set_consent_role(&backend, "k-cr", None)
            .await
            .unwrap();
        assert_eq!(consent_role_of(&backend, "k-cr").await.unwrap(), None);

        // Unknown key: setter errors, resolver stays total (Ok(None)).
        assert!(crate::federation::FederationDirectory::set_consent_role(
            &backend,
            "k-missing",
            Some("peer")
        )
        .await
        .is_err());
        assert_eq!(consent_role_of(&backend, "k-missing").await.unwrap(), None);

        // Unrecognized token: rejected at admission (backend-symmetric).
        assert!(crate::federation::FederationDirectory::set_consent_role(
            &backend,
            "k-cr",
            Some("emperor")
        )
        .await
        .is_err());

        // The literal stored default 'unregistered' normalizes to wire
        // None on set (stored/wire forms cohere).
        crate::federation::FederationDirectory::set_consent_role(
            &backend,
            "k-cr",
            Some(consent_role::UNREGISTERED),
        )
        .await
        .unwrap();
        assert_eq!(consent_role_of(&backend, "k-cr").await.unwrap(), None);

        // consent_role does NOT enter persist_row_hash (OQ-1 exclusion).
        let mut a = fix_key("k-hash", "primitive-cr", "k-hash");
        a.consent_role = None;
        let h0 = crate::federation::types::compute_persist_row_hash(&a).unwrap();
        a.consent_role = Some(consent_role::PARTNERED.into());
        let h1 = crate::federation::types::compute_persist_row_hash(&a).unwrap();
        assert_eq!(h0, h1, "consent_role must not affect persist_row_hash");
    }

    /// Mission category §4 "Backend parity" (placeholder for the
    /// Phase-1.4 conformance suite): a decomposed CompleteTrace lands
    /// on the in-memory backend with the right row counts, dedup
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

    // (v7.0.0: the `phase_2_surfaces_return_not_implemented` test was
    // removed with the vestigial `Backend` Phase-2/3 stubs — those
    // capabilities ship via the per-capability service traits with full
    // pg/sqlite parity; see `store::backend`.)

    // ─── FederationDirectory tests ─────────────────────────────────

    use crate::federation::{
        Attestation, FederationDirectory, KeyRecord, Revocation, SignedAttestation,
        SignedKeyRecord, SignedRevocation,
    };

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
        crate::federation::tier_ingest::test_support::reseal(row);
    }

    fn fix_attestation(
        id: &str,
        attesting: &str,
        attested: &str,
        scrub_key_id: &str,
    ) -> Attestation {
        let mut row = Attestation {
            attestation_id: id.into(),
            attesting_key_id: attesting.into(),
            attested_key_id: attested.into(),
            attestation_type: crate::federation::types::attestation_type::SCORES.into(),
            weight: Some(1.0),
            asserted_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            expires_at: None,
            // v2.4.0 admission gate (CIRISPersist#102 Ask 3) — `scores`
            // attestations need a versioned mechanism-descriptive
            // dimension. Test rows use a generic identity-binding
            // shape that passes the four-test gate.
            attestation_envelope: serde_json::json!({
                "id": id,
                "dimension": "identity_binding:v1",
                "score": 1.0,
                "confidence": 0.9,
            }),
            original_content_hash: "abc123".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
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
            be.plant_attestation_below_the_door(a);
        }

        {
            let mut sup = fix_attestation("w-self-widened", "k530", "k530", "k530");
            sup.attestation_type = crate::federation::types::attestation_type::SUPERSEDES.into();
            sup.attestation_envelope["references_attestation_id"] = serde_json::json!("w-self");
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
        assert_eq!(
            ids,
            vec!["s-family".to_string(), "s-self".to_string()],
            "only suppressed federation-tier rows, ASC by attestation_id"
        );

        // keyset cursor resumes strictly after the given id.
        let after: Vec<String> = be
            .list_widening_candidates(Some("s-family"), 100)
            .await
            .expect("page 2")
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(after, vec!["s-self".to_string()]);
    }

    /// CIRISPersist#807 — **a row already published WIDER by other means is
    /// not awaiting anybody.**
    ///
    /// The owner-binding case CIRISServer measured: setup writes
    /// `delegates_to(owner → node)` at `self`, and the announce publishes a
    /// FRESH `delegates_to` at federation scope rather than a `supersedes`
    /// (which is correct — see `owner_binding_widening_is_not_visible_to_a_peer_807`
    /// for why a `supersedes` announce would be invisible to every peer). The
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
            be.plant_attestation_below_the_door(a);
        };
        // The `self` binding alone IS a candidate — nothing publishes it yet.
        push("binding-self", cohort_scope::SELF);
        let ids: Vec<String> = be
            .list_widening_candidates(None, 100)
            .await
            .expect("page")
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(
            ids,
            vec!["binding-self".to_string()],
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
        {
            let mut a = fix_attestation("other-self", "owner", "node-b", "owner");
            a.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
            a.tier = attestation_tier::FEDERATION.to_string();
            a.cohort_scope = cohort_scope::SELF.to_string();
            resign_fix(&mut a);
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
            vec!["other-self".to_string()],
            "#807: the exclusion must match the CLAIM (attester, type, attested key, dimension) \
             — a wider row about a different subject settles nothing"
        );
    }

    // ── v17.4.0 (FSD-005 Appendix C) — scores read surface parity ──

    fn scores_base() -> chrono::DateTime<chrono::Utc> {
        chrono::TimeZone::timestamp_opt(&chrono::Utc, 1_700_000_000, 0).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    async fn mem_put_score(
        be: &SqliteBackend,
        id: &str,
        attester: &str,
        subject: &str,
        dimension: &str,
        score: f64,
        weight: f64,
        secs: i64,
    ) {
        let _ = be
            .put_public_key(SignedKeyRecord {
                record: fix_key(attester, attester, attester),
            })
            .await;
        let mut a = fix_attestation(id, attester, attester, attester);
        a.weight = Some(weight);
        a.asserted_at = scores_base() + chrono::Duration::seconds(secs);
        a.attestation_envelope = serde_json::json!({
            "dimension": dimension, "score": score, "confidence": weight,
        });
        a.subject_key_ids = vec![subject.into()];
        resign_fix(&mut a);
        be.put_attestation(SignedAttestation { attestation: a })
            .await
            .unwrap();
    }

    async fn mem_put_composer(
        be: &SqliteBackend,
        id: &str,
        attester: &str,
        ty: &str,
        references: &str,
        secs: i64,
    ) {
        let _ = be
            .put_public_key(SignedKeyRecord {
                record: fix_key(attester, attester, attester),
            })
            .await;
        let mut a = fix_attestation(id, attester, attester, attester);
        a.attestation_type = ty.into();
        a.asserted_at = scores_base() + chrono::Duration::seconds(secs);
        a.attestation_envelope =
            serde_json::json!({ "references_attestation_id": references, "reason": "t" });
        a.subject_key_ids = vec![];
        resign_fix(&mut a);
        be.put_attestation(SignedAttestation { attestation: a })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sqlite_list_attestation_log_owner_scope() {
        // #455 — backend parity for the owner LOG walk: lifecycle-blind (a
        // withdrawn score stays) + composers visible in the full walk;
        // subject seek returns subject-bearing rows only.
        use crate::federation::FederationDirectory;
        let be = test_backend();
        mem_put_score(&be, "live", "k1", "subj", "trust:demo:v1", 0.5, 1.0, 10).await;
        mem_put_score(&be, "gone", "k2", "subj", "trust:demo:v1", 0.5, 1.0, 20).await;
        mem_put_composer(&be, "wd", "k2", "withdraws", "gone", 30).await;
        // gated Live read hides the withdrawn "gone".
        let gated: Vec<String> = be
            .list_scores(
                "",
                crate::read::AttestationFilter {
                    subject_key_id: Some("subj".into()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(gated, vec!["live"]);
        // subject log: gone + live (lifecycle-blind; subjectless wd excluded).
        let mut sids: Vec<String> = be
            .list_attestation_log(Some("subj"), None, 100)
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        sids.sort();
        assert_eq!(sids, vec!["gone", "live"]);
        // full log: every federation row incl. the composer.
        let mut fids: Vec<String> = be
            .list_attestation_log(None, None, 100)
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        fids.sort();
        assert_eq!(fids, vec!["gone", "live", "wd"]);
    }

    #[tokio::test]
    async fn sqlite_scores_read_resolve_and_mirror() {
        use crate::federation::FederationDirectory;
        let be = test_backend();
        mem_put_score(&be, "a", "k1", "subj", "trust:demo:v1", 0.5, 1.0, 10).await;
        mem_put_score(&be, "b", "k2", "subj", "trust:demo:v1", 0.5, 1.0, 20).await;
        mem_put_score(&be, "c", "k3", "subj", "trust:demo:v1", 0.5, 1.0, 30).await;
        let filter = crate::read::AttestationFilter {
            subject_key_id: Some("subj".into()),
            ..Default::default()
        };
        // newest-first
        let ids: Vec<String> = be
            .list_scores("", filter.clone(), None, 100)
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(ids, vec!["c", "b", "a"]);
        // cursor pagination
        let p1 = be.list_scores("", filter.clone(), None, 2).await.unwrap();
        assert_eq!(p1.items.len(), 2);
        let cur = p1.next_cursor.expect("full page");
        let p2 = be
            .list_scores("", filter.clone(), Some(cur), 2)
            .await
            .unwrap();
        assert_eq!(p2.items.len(), 1);
        assert_eq!(p2.items[0].attestation_id, "a");
        // resolve: 3 contributors, mean 0.5 → Supported
        let v = be
            .resolve_scores("", filter.clone(), "cc-4.4.2-signed-mean".into(), false)
            .await
            .unwrap();
        assert_eq!(v.contributor_count, 3);
        assert_eq!(v.band, crate::read::ConfidenceBand::Supported);
        // withdraw k3 → drops from both list (default Live) and fold
        mem_put_composer(&be, "w", "k3", "withdraws", "c", 40).await;
        let ids: Vec<String> = be
            .list_scores("", filter.clone(), None, 100)
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(ids, vec!["b", "a"], "withdrawn hidden by default");
        let v = be
            .resolve_scores("", filter, "cc-4.4.2-signed-mean".into(), false)
            .await
            .unwrap();
        assert_eq!(v.contributor_count, 2, "k3 withdrawn → out of fold");
    }

    /// v30.8.0 (CIRISPersist#596 item 1) — give `revoker` the `slash` authority
    /// that revoking SOMEONE ELSE'S key now requires.
    ///
    /// These fixtures test revocation MECHANICS (round-trip, region,
    /// anti-rollback, PQC attach), not who may revoke — so they get the
    /// authority they would hold in production rather than being rewritten as
    /// self-revocations, which would quietly narrow what they exercise.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn grant_slash(backend: &SqliteBackend, revoker: &str) {
        backend.set_node_key_id("rev-authority-node");
        // NOT self-registering: these fixtures register their own keys with
        // their own pubkeys, and `register_hybrid_key`'s deterministic ones
        // collide as a content conflict. Call this AFTER the fixture has
        // registered the revoker.
        crate::federation::admission::r2_test_support::confer_scope_from_trusted_root(
            backend,
            "rev-authority-node",
            "rev-authority-root",
            revoker,
            crate::federation::admission::DELEGATION_SCOPE_SLASH,
        )
        .await;
    }

    /// v38.0.0 (CIRISPersist#721) — **the per-key DSAR delete announces like
    /// its Art.-17 sibling.** Same fixture shape as the dsar tests below.
    #[tokio::test]
    async fn delete_traces_for_agent_announces_like_its_sibling_721() {
        use crate::federation::FederationDirectory as _;
        use crate::store::Backend as _;
        let backend = test_backend();
        // v57.0.0 (#988 item 2) — a hard_case row needs this node's key.
        crate::federation::hard_case::test_support::declare_node(&backend, "memory-test-node")
            .await;
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
        crate::federation::hard_case::test_support::declare_node(&backend, "memory-test-node")
            .await;
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
        for k in ["adv-a", "adv-b"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, k, k),
                })
                .await
                .unwrap();
        }
        let mut ids = Vec::new();
        for i in 0..7 {
            let id = format!("adv-{i}");
            let mut row = fix_attestation(&id, "adv-a", "adv-b", "adv-a");
            row.attestation_type = crate::federation::types::attestation_type::SCORES.into();
            resign_fix(&mut row);
            backend
                .put_attestation(crate::federation::SignedAttestation { attestation: row })
                .await
                .expect("seed");
            ids.push(id);
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
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, k, k),
                })
                .await
                .unwrap();
        }

        // Expired, re-derivable claim → reapable.
        let mut expired = fix_attestation("reap-expired", "reap-a", "reap-b", "reap-a");
        expired.attestation_type = crate::federation::types::attestation_type::SCORES.into();
        expired.expires_at = Some(past);
        resign_fix(&mut expired);
        // Expired WITHDRAWAL → evidence; the door must refuse it.
        let mut expired_withdraws = fix_attestation("reap-withdraws", "reap-a", "reap-b", "reap-a");
        expired_withdraws.attestation_type =
            crate::federation::types::attestation_type::WITHDRAWS.into();
        expired_withdraws.expires_at = Some(past);
        resign_fix(&mut expired_withdraws);
        // Not yet expired → not offered at all.
        let mut live = fix_attestation("reap-live", "reap-a", "reap-b", "reap-a");
        live.attestation_type = crate::federation::types::attestation_type::SCORES.into();
        live.expires_at = Some(future);
        resign_fix(&mut live);

        for row in [expired, expired_withdraws, live] {
            backend
                .put_attestation(crate::federation::SignedAttestation { attestation: row })
                .await
                .expect("seed");
        }

        // The sweep only ever offers rows past their stated expiry.
        let offered = backend
            .list_expired_attestation_ids(now, 100, 0)
            .await
            .expect("list expired");
        assert!(
            !offered.contains(&"reap-live".to_string()),
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
            crate::federation::FederationDirectory::purge_attestation_v31(
                &backend,
                "reap-withdraws"
            )
            .await
            .is_err(),
            "#768: the purge DOOR refuses a withdrawal on its own authority — the query \
             filter is an optimisation, not the guarantee"
        );
        assert!(
            backend
                .get_attestation("reap-expired")
                .await
                .unwrap()
                .is_none(),
            "#768: the expired claim is gone — its producer said when it stops speaking"
        );
        assert!(
            backend
                .get_attestation("reap-withdraws")
                .await
                .unwrap()
                .is_some(),
            "#768: an expired WITHDRAWS must survive — a retraction is a statement about \
             the past, and the purge door refuses it whatever this sweep believes. A bulk \
             DELETE on expires_at would have removed it silently."
        );
        assert!(
            backend
                .get_attestation("reap-live")
                .await
                .unwrap()
                .is_some(),
            "#768: an unexpired row is untouched"
        );

        // PR #769 review — **the sweep must not wedge behind refusals.**
        // A prefix of expired-but-unpurgeable rows (a withdrawal is refused
        // today and forever) previously re-offered itself every pass, so a
        // purgeable row behind it was never reached. Seed one more expired
        // withdrawal OLDER than a purgeable claim and require the claim to
        // still be reaped.
        let older = now - chrono::Duration::hours(9);
        let mut blocker = fix_attestation("reap-blocker", "reap-a", "reap-b", "reap-a");
        blocker.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.into();
        blocker.expires_at = Some(older);
        resign_fix(&mut blocker);
        let mut behind = fix_attestation("reap-behind", "reap-a", "reap-b", "reap-a");
        behind.attestation_type = crate::federation::types::attestation_type::SCORES.into();
        behind.expires_at = Some(older + chrono::Duration::minutes(1));
        resign_fix(&mut behind);
        for row in [blocker, behind] {
            backend
                .put_attestation(crate::federation::SignedAttestation { attestation: row })
                .await
                .expect("seed blocked pair");
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
            backend
                .get_attestation("reap-behind")
                .await
                .unwrap()
                .is_none(),
            "#768: the row behind the immovable prefix was reaped"
        );
        assert!(
            backend
                .get_attestation("reap-blocker")
                .await
                .unwrap()
                .is_some(),
            "#768: and the withdrawal it paged past is still there"
        );

        // PR #769 review round 2 — **the projections go with the row.**
        // Memory holds `consent_peer_set` and `signed_wire_index` like the
        // SQL backends, and the reaper's first shape left both behind: an
        // expired grant purged while `list_consent_peers` still returned
        // the peer it authorised. Seed a projection row against a purgeable
        // attestation and require it gone.
        let mut granted = fix_attestation("reap-grant", "reap-a", "reap-b", "reap-a");
        granted.attestation_type = crate::federation::types::attestation_type::SCORES.into();
        granted.expires_at = Some(past);
        resign_fix(&mut granted);
        backend
            .put_attestation(crate::federation::SignedAttestation {
                attestation: granted,
            })
            .await
            .expect("seed granted");
        backend
            .test_execute(&format!(
                "INSERT OR REPLACE INTO consent_peer_set (node_key_id, for_key_id, peer_key_id, \
                    source_attestation_id, asserted_at) \
                 VALUES ('reap-a', 'reap-a', 'reap-b', 'reap-grant', '{}')",
                now.to_rfc3339()
            ))
            .await;
        let (p3, _) = backend
            .reap_expired_attestations(now, 10)
            .await
            .expect("reap grant");
        assert!(p3 >= 1, "#768: the expired grant is reaped");
        assert!(
            backend.test_query_i64(
                "SELECT COUNT(*) FROM consent_peer_set WHERE source_attestation_id = 'reap-grant'"
            ) == 0,
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
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::FederationDirectory as _;
        let backend = test_backend();
        ts::register_hybrid_key(&backend, "granter-721").await;
        ts::register_hybrid_key(&backend, "imposter-721").await;
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("subject-721", "subject-721", "subject-721"),
            })
            .await
            .unwrap();
        let grant = || crate::federation::TrustGrant {
            key: "subject-721".into(),
            trust_type: crate::federation::TrustType::Temporary,
            trust_relationship: crate::federation::TrustRelationship::Direct,
            trust_domains: None,
            trusted_by: "granter-721".into(),
            expires_at: None,
        };

        // Forged signature: refused, naming the authority failure.
        let mut forged = ts::signed_trust_grant(grant());
        forged.signature_classical_base64 = {
            let mut c: Vec<char> = forged.signature_classical_base64.chars().collect();
            c[10] = if c[10] == 'A' { 'B' } else { 'A' };
            c.into_iter().collect()
        };
        let err = backend.grant_trust(forged).await.unwrap_err();
        assert!(
            format!("{err}").contains("trust grant authority"),
            "a forged grant must refuse as an authority failure: {err}"
        );

        // Imposter: signs correctly with ITS OWN key while naming the
        // granter — the signature cannot verify against the granter's
        // directory-pinned keys (the gate asks about the SIGNER).
        let bytes = crate::federation::admission::trust_grant_signing_bytes(&grant()).unwrap();
        let sig = ts::threshold_sign("imposter-721", &bytes);
        let imposter = crate::federation::SignedTrustGrant {
            grant: grant(),
            signature_classical_base64: sig.ed25519_signature_base64,
            signature_pqc_base64: sig.mldsa65_signature_base64,
        };
        let err = backend.grant_trust(imposter).await.unwrap_err();
        assert!(format!("{err}").contains("trust grant authority"), "{err}");
        assert!(
            backend.lookup_trust("subject-721").await.unwrap().is_none(),
            "no refused grant may half-land"
        );

        // The honest granter lands.
        backend
            .grant_trust(ts::signed_trust_grant(grant()))
            .await
            .expect("a proven grant admits");
        let row = backend.lookup_trust("subject-721").await.unwrap().unwrap();
        assert_eq!(row.trusted_by, "granter-721");

        // Only the granter withdraws its own grant.
        let err = backend
            .revoke_trust(ts::signed_trust_revocation("subject-721", "imposter-721"))
            .await
            .unwrap_err();
        assert!(
            format!("{err}").contains("only the"),
            "a non-granter revocation must refuse by name: {err}"
        );
        backend
            .revoke_trust(ts::signed_trust_revocation("subject-721", "granter-721"))
            .await
            .expect("the granter's revocation lands");
        // Idempotent second revoke.
        backend
            .revoke_trust(ts::signed_trust_revocation("subject-721", "granter-721"))
            .await
            .expect("revoking an expired grant is a no-op");
    }

    /// v38.0.0 (CIRISPersist#709) — **a bystander's registration is not a
    /// vote.** The partner-licence quorum denominator was `count(identity_type
    /// = steward)` over the whole directory — no validity window, no
    /// revocation fold — while M is signed and frozen at mint. So the SAME
    /// signed bytes admitted on a fresh node and refused on a synced one
    /// ("quorum policy 2/33 refused"), non-convergent and remotely inflatable
    /// (steward-shaped rows arrive over replication and never leave). The
    /// denominator now folds the two liveness facts persist itself holds:
    /// expiry and revocation.
    #[tokio::test]
    async fn partner_quorum_denominator_folds_liveness_709() {
        use crate::federation::operational::test_support as op;
        use crate::federation::FederationDirectory as _;
        let backend = test_backend();

        let stewards: Vec<op::Identity> = (0..3)
            .map(|i| op::Identity::new(&format!("s709-{i}")))
            .collect();
        for s in &stewards {
            backend
                .put_public_key(SignedKeyRecord {
                    record: s.steward_key_record(),
                })
                .await
                .unwrap();
        }
        let refs: Vec<&op::Identity> = stewards.iter().collect();
        let now =
            crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());

        // THE CONTROL — 2 of 3 seated stewards is a strict majority.
        backend
            .put_partner_record(op::signed_partner_record(
                &uuid::Uuid::new_v4().to_string(),
                "lic-709-control",
                1,
                "active",
                now,
                &refs[..2],
                2,
                false,
            ))
            .await
            .expect("2-of-3 must admit before the accumulation");

        // THE ACCUMULATION — thirty EXPIRED steward-shaped rows, planted as
        // state (what a directory looks like after months of replication;
        // the door's own gates are not the subject here, the DENOMINATOR is).
        for i in 0..30 {
            let mut rec = op::Identity::new(&format!("expired709-{i}")).steward_key_record();
            rec.valid_until = Some("2021-01-01T00:00:00Z".parse().unwrap());
            backend.seed_key_row_unchecked_for_test(rec);
        }
        // …and one REVOKED live steward, through the real doors.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("revoked709", "revoked709", "revoked709"),
            })
            .await
            .ok();
        // identity_type must be steward for the row to enter the scan.
        backend
            .test_seam_set_key_identity_type(
                "revoked709",
                crate::federation::types::identity_type::STEWARD,
            )
            .await
            .expect("identity_type seam");
        backend
            .put_revocation(SignedRevocation {
                revocation: fix_revocation("rev709", "revoked709", "revoked709", "revoked709"),
            })
            .await
            .expect("revocation admits");

        // THE SAME two signers, a NEW licence: the denominator must still be
        // the 3 seated stewards — an expired row is not seated, a revoked row
        // is not seated, and a bystander's registration is not a vote.
        backend
            .put_partner_record(op::signed_partner_record(
                &uuid::Uuid::new_v4().to_string(),
                "lic-709-after",
                1,
                "active",
                now,
                &refs[..2],
                2,
                false,
            ))
            .await
            .expect(
                "2-of-3 SEATED must still admit — 30 expired rows and a revoked one \
                 inflated the denominator (#709)",
            );
    }

    // ─── v31.4.0 (CIRISPersist#682 / #668) — the identity plane's serve
    //     cursor, memory arm. Assertion bodies shared with the sqlite and
    //     postgres arms; only the PLANT is backend-specific.

    fn fix_revocation(id: &str, revoked: &str, revoking: &str, scrub_key_id: &str) -> Revocation {
        // v21.0.0 (#502 E1) — real hybrid sig by the revoking key.
        // v31.0.0 (#659) — and the typed columns are BOUND INTO the bytes that
        // signature covers, through the one shared producer, so a fixture
        // cannot certify a revocation this substrate's own put door refuses.
        crate::federation::tier_ingest::test_support::seal_revocation(Revocation {
            revocation_id: id.into(),
            revoked_key_id: Some(revoked.into()),
            revoked_key_sha256_ed25519_raw:
                crate::federation::tier_ingest::test_support::subject_digest_of(revoked),
            revoking_key_id: revoking.into(),
            reason: Some("test".into()),
            revoked_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            effective_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            revocation_envelope: serde_json::json!({"id": id}),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            observed_region: crate::federation::verify_coord::region::US.into(),
            revoked_after: None,
            persist_row_hash: String::new(),
        })
    }

    // ── #236 CC 4.4.3.4.3 / CC 3.4.7.3 — reject-agency-on-node-key gate ───

    /// Build a `delegates_to` row from `attesting` to `attested` carrying
    /// the given scope set (array wire shape). Re-uses `fix_attestation`
    /// then overrides the type + scope envelope.
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

    fn fix_node_delegates_to(
        id: &str,
        attesting: &str,
        attested: &str,
        scrub_key_id: &str,
        scope: &[&str],
    ) -> Attestation {
        let mut att = fix_attestation(id, attesting, attested, scrub_key_id);
        att.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
        att.attestation_envelope = serde_json::json!({
            "id": id,
            "scope": scope.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        });
        resign_fix(&mut att); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        att
    }

    /// Register `owner` (user) + `node` (node-only) + an `agent` recipient.
    /// v50.0.0 (CIRISPersist#928, final check) — the memory backend writes a
    /// `withdraws` and its admission depth under ONE lock (so there is no
    /// half-write to witness); an identical re-put of a row whose depth is
    /// missing records it again (idempotent repair).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    async fn withdraws_depth_is_repaired_on_an_identical_reput_sqlite() {
        use crate::federation::FederationDirectory as _;
        let backend = test_backend();
        let w = crate::federation::rc5_adopts_invariants::bodies::deferred_withdraws(
            &backend,
            "wdepth-mem",
        )
        .await;
        let id = w.attestation_id.clone();
        backend
            .put_attestation(SignedAttestation {
                attestation: w.clone(),
            })
            .await
            .expect("deferred withdraws");
        backend
            .test_execute(&format!(
                "DELETE FROM federation_withdraws_admission_depths WHERE attestation_id = '{id}'"
            ))
            .await;
        assert_eq!(backend.withdraws_admission_depth(&id).await.unwrap(), None);
        assert_eq!(
            backend
                .put_attestation(SignedAttestation { attestation: w })
                .await
                .unwrap(),
            crate::federation::AttestationOutcome::AlreadyHeld
        );
        assert_eq!(
            backend.withdraws_admission_depth(&id).await.unwrap(),
            Some(crate::federation::DEFAULT_DELEGATION_DEPTH)
        );
    }

    /// v50.0.0 (CIRISPersist#925 ask 5) — a fused `{node,agent}` /
    /// `{node,user}` key can no longer be MINTED: CC 3.4.7.3 Clause A refuses
    /// it at `put_public_key`. Clause B exists for the fused keys minted
    /// before that door, so its witnesses plant one BELOW the door: register
    /// the key as `node`, then rewrite the stored set.
    async fn plant_pre_clause_a_key(backend: &SqliteBackend, mut rec: KeyRecord) {
        let fused = std::mem::replace(&mut rec.identity_type, "node".into());
        let key = rec.key_id.clone();
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("register as node");
        backend
            .test_seam_set_key_identity_type(&key, &fused)
            .await
            .expect("just registered");
    }

    /// v50.0.0 (CIRISPersist#925 ask 5, CC 3.4.7.3 Clause A) — `node` is
    /// exclusive at the key-record door: a `{node,agent}` or `{node,user}` key
    /// is refused by name and nothing is stored; a substrate-side
    /// co-location (`canonical`-free here: `node,steward`) stays admissible.
    #[tokio::test]
    async fn clause_a_node_key_cannot_carry_an_actor_role_at_mint() {
        use crate::federation::types::identity_type as it;
        let backend = test_backend();
        for actor in [it::AGENT, it::USER] {
            let mut k = fix_key(&format!("fused-{actor}"), "x", &format!("fused-{actor}"));
            k.identity_type = format!("{actor},{}", it::NODE);
            let err = backend
                .put_public_key(SignedKeyRecord { record: k })
                .await
                .expect_err("Clause A: a fused node key is not minted");
            assert!(
                matches!(
                    err,
                    crate::federation::Error::NodeIdentityNotExclusive { .. }
                ),
                "refused by the Clause A error, not a neighbouring gate: {err}"
            );
            assert!(crate::federation::FederationDirectory::lookup_public_key(
                &backend,
                &format!("fused-{actor}")
            )
            .await
            .unwrap()
            .is_none());
        }
        let mut ok = fix_key("node-steward", "x", "node-steward");
        ok.identity_type = format!("{},{}", it::NODE, it::STEWARD);
        backend
            .put_public_key(SignedKeyRecord { record: ok })
            .await
            .expect("node + a substrate-side role is conformant");
    }

    async fn bootstrap_node_agency(backend: &SqliteBackend) {
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        let mut owner = fix_key("owner", "owner", "registry-steward");
        owner.identity_type = crate::federation::types::identity_type::USER.into();
        backend
            .put_public_key(SignedKeyRecord { record: owner })
            .await
            .unwrap();
        let mut node = fix_key("node-key", "node", "registry-steward");
        node.identity_type = crate::federation::types::identity_type::NODE.into();
        backend
            .put_public_key(SignedKeyRecord { record: node })
            .await
            .unwrap();
        let mut agent = fix_key("agent-key", "agent", "registry-steward");
        agent.identity_type = crate::federation::types::identity_type::AGENT.into();
        backend
            .put_public_key(SignedKeyRecord { record: agent })
            .await
            .unwrap();
    }

    /// (b) delegates_to → node key carrying agency:* → REJECTED + not stored.
    /// THE load-bearing CC 3.4.7.3 guard.
    /// v38.6.0 (CIRISPersist#773, CC 3.4.7.3 Clause B) — **the hybrid
    /// loophole: fusing `agent` onto a node key must NOT repeal the gate.**
    ///
    /// The gate used to test `identity_type == {node}` exactly, so a
    /// `{node,agent}` recipient fell through and "infrastructure must not
    /// have agency" silently stopped applying. Nothing witnessed it — the
    /// rejection test below only ever used a pure-node key, so the gate
    /// could be repealed by a one-token edit and the suite stayed green.
    ///
    /// Clause A forbids MINTING such a key, but a non-conformant key that
    /// already exists is still a key in the data and still a possible
    /// `delegates_to` recipient. Non-conformance is a reason to re-mint,
    /// never a reason the gate stops applying.
    #[tokio::test]
    async fn hybrid_node_agent_key_still_refuses_agency_773() {
        use crate::federation::types::{delegation_scope as ds, identity_type};
        let backend = test_backend();
        bootstrap_node_agency(&backend).await;

        // A key carrying BOTH roles — the shape a "consolidation" produces.
        let mut hybrid = fix_key("hybrid-key", "hybrid", "registry-steward");
        hybrid.identity_type = format!("{},{}", identity_type::NODE, identity_type::AGENT);
        plant_pre_clause_a_key(&backend, hybrid).await;

        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_node_delegates_to(
                    "d-agency-hybrid",
                    "owner",
                    "hybrid-key",
                    "owner",
                    &[ds::INFRA_SERVE, ds::AGENCY_ACT_ON_BEHALF],
                ),
            })
            .await
            .expect_err(
                "#773: a {node,agent} recipient must STILL be refused — membership, not \
                 exclusivity. Passing here is the escape hatch: consolidating two keys into \
                 one hybrid would silently switch the property off.",
            );
        assert!(
            matches!(err, crate::federation::Error::NodeAgencyForbidden { .. }),
            "#773: and it refuses by the SAME typed error, not some neighbouring gate: {err}"
        );

        // The other half of the rule: a key with NO node role is untouched —
        // an agent legitimately carries agency, and this must not over-reject.
        let mut brain = fix_key("brain-key", "brain", "registry-steward");
        brain.identity_type = identity_type::AGENT.into();
        backend
            .put_public_key(SignedKeyRecord { record: brain })
            .await
            .expect("register agent key");
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_node_delegates_to(
                    "d-agency-brain",
                    "owner",
                    "brain-key",
                    "owner",
                    &[ds::AGENCY_ACT_ON_BEHALF],
                ),
            })
            .await
            .expect(
                "#773: an agent key legitimately carries agency — the gate is about the \
                     NODE role, not about all keys",
            );
    }

    #[tokio::test]
    async fn put_and_lookup_public_key() {
        let backend = test_backend();
        let key = fix_key("persist-steward", "persist", "persist-steward");
        backend
            .put_public_key(SignedKeyRecord {
                record: key.clone(),
            })
            .await
            .unwrap();

        // Disambiguate: both Backend and FederationDirectory traits
        // expose `lookup_public_key`; here we want the federation
        // KeyRecord shape, not the legacy VerifyingKey.
        let got = FederationDirectory::lookup_public_key(&backend, "persist-steward")
            .await
            .unwrap();
        assert!(got.is_some());
        let got = got.unwrap();
        assert_eq!(got.key_id, "persist-steward");
        assert_eq!(got.identity_ref, "persist");
        // persist_row_hash is server-computed.
        assert_eq!(got.persist_row_hash.len(), 64);
        assert_ne!(got.persist_row_hash, key.persist_row_hash);
    }

    #[tokio::test]
    async fn lookup_unknown_returns_none() {
        let backend = test_backend();
        let got = FederationDirectory::lookup_public_key(&backend, "missing")
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn idempotent_put_same_content() {
        let backend = test_backend();
        let key = fix_key("persist-steward", "persist", "persist-steward");
        backend
            .put_public_key(SignedKeyRecord {
                record: key.clone(),
            })
            .await
            .unwrap();
        // Same content — idempotent no-op.
        backend
            .put_public_key(SignedKeyRecord { record: key })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn put_conflict_different_content() {
        let backend = test_backend();
        let mut key1 = fix_key("k1", "primitive-a", "k1");
        key1.identity_type = "primitive".into();
        let mut key2 = fix_key("k1", "primitive-b", "k1");
        key2.identity_type = "primitive".into();
        backend
            .put_public_key(SignedKeyRecord { record: key1 })
            .await
            .unwrap();
        let err = backend
            .put_public_key(SignedKeyRecord { record: key2 })
            .await
            .unwrap_err();
        assert!(matches!(err, crate::federation::Error::Conflict(_)));
    }

    #[tokio::test]
    async fn lookup_keys_for_identity_filters() {
        let backend = test_backend();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-persist-1", "persist", "k-persist-1"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-persist-2", "persist", "k-persist-2"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-other", "lens", "k-other"),
            })
            .await
            .unwrap();
        let persist_keys = backend.lookup_keys_for_identity("persist").await.unwrap();
        assert_eq!(persist_keys.len(), 2);
        let lens_keys = backend.lookup_keys_for_identity("lens").await.unwrap();
        assert_eq!(lens_keys.len(), 1);
        let none = backend.lookup_keys_for_identity("missing").await.unwrap();
        assert!(none.is_empty());
    }

    /// v2.6.0 (CIRISPersist#105) — class-based enumeration via
    /// `list_keys_by_identity_type`. Two `steward` rows + one
    /// `primitive` row; the steward query returns the two in
    /// `key_id` lex order, the primitive query returns the one row,
    /// and an unknown identity_type returns the empty Vec.
    ///
    /// Mirrors the sibling `federation_list_keys_by_identity_type_round_trip`
    /// in `store::sqlite::tests` (uses non-accord identity_types so
    /// the memory + sqlite + postgres impls can run the same scenario
    /// without V048's hardware-attestation surface friction).
    #[tokio::test]
    async fn list_keys_by_identity_type_class_lookup() {
        let backend = test_backend();
        // Insert in reverse lex order to confirm ORDER BY key_id sort.
        let mut steward_b = fix_key("steward-bravo", "steward-bravo", "steward-bravo");
        steward_b.identity_type = crate::federation::types::identity_type::STEWARD.into();
        let mut steward_a = fix_key("steward-alpha", "steward-alpha", "steward-alpha");
        steward_a.identity_type = crate::federation::types::identity_type::STEWARD.into();
        let prim = fix_key("prim-1", "prim-1", "prim-1"); // PRIMITIVE by default

        backend
            .put_public_key(SignedKeyRecord { record: steward_b })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord { record: steward_a })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord { record: prim })
            .await
            .unwrap();

        let steward_rows = backend
            .list_keys_by_identity_type(crate::federation::types::identity_type::STEWARD)
            .await
            .unwrap();
        assert_eq!(steward_rows.len(), 2);
        assert_eq!(steward_rows[0].key_id, "steward-alpha");
        assert_eq!(steward_rows[1].key_id, "steward-bravo");

        let prim_rows = backend
            .list_keys_by_identity_type(crate::federation::types::identity_type::PRIMITIVE)
            .await
            .unwrap();
        assert_eq!(prim_rows.len(), 1);
        assert_eq!(prim_rows[0].key_id, "prim-1");

        let empty = backend
            .list_keys_by_identity_type("unknown_type")
            .await
            .unwrap();
        assert!(empty.is_empty());
    }

    // v30.8.0 (CIRISPersist#596 item 1) — gated with `grant_slash`, which needs
    // the conferral builder in `r2_test_support` (itself cfg(any(sqlite,
    // postgres)) because it requires a real signing path). A cfg on the helper
    // but not its CALL SITES is the v30.4.1 `_pyffi` defect exactly, and the
    // no-feature leg is what catches it. Coverage note: this test stops running
    // on the default build; its subject (revocation mechanics on the memory
    // backend) is covered on every featured leg.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    /// v2.6.0 (CIRISPersist#108) — confirm `persist_row_hash` is
    /// surfaced on every federation row-read path. Verify will pass
    /// the hex value into `FederationProvenance::persist_row_hash`
    /// (Option<String>) so a downstream consumer can correlate the
    /// attestation back to persist's storage. Two reads of the same
    /// row return the same hash (idempotency) and the hash is
    /// non-empty (the server computed it on the put).
    #[tokio::test]
    async fn persist_row_hash_surfaces_on_federation_reads() {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        use crate::federation::FederationDirectory;
        let backend = test_backend();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("steward-1", "steward-1", "steward-1"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-target", "primitive-a", "steward-1"),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation("att-1", "steward-1", "k-target", "steward-1"),
            })
            .await
            .unwrap();
        grant_slash(&backend, "steward-1").await;
        backend
            .put_revocation(SignedRevocation {
                revocation: fix_revocation("rev-1", "k-target", "steward-1", "steward-1"),
            })
            .await
            .unwrap();

        // Keys.
        let key1 = FederationDirectory::lookup_public_key(&backend, "k-target")
            .await
            .unwrap()
            .expect("row exists");
        assert!(!key1.persist_row_hash.is_empty(), "key row_hash empty");
        let key2 = FederationDirectory::lookup_public_key(&backend, "k-target")
            .await
            .unwrap()
            .expect("row exists");
        assert_eq!(
            key1.persist_row_hash, key2.persist_row_hash,
            "key persist_row_hash differs between reads"
        );

        // Attestations.
        let att1 = backend.all_attestations_for("k-target").await.unwrap();
        assert_eq!(att1.len(), 1);
        assert!(
            !att1[0].persist_row_hash.is_empty(),
            "attestation row_hash empty"
        );
        let att2 = backend.all_attestations_for("k-target").await.unwrap();
        assert_eq!(att1[0].persist_row_hash, att2[0].persist_row_hash);

        // Revocations.
        let rev1 = backend.revocations_for("k-target").await.unwrap();
        assert_eq!(rev1.len(), 1);
        assert!(
            !rev1[0].persist_row_hash.is_empty(),
            "revocation row_hash empty"
        );
        let rev2 = backend.revocations_for("k-target").await.unwrap();
        assert_eq!(rev1[0].persist_row_hash, rev2[0].persist_row_hash);
    }

    #[tokio::test]
    async fn put_attestation_requires_both_keys_exist() {
        let backend = test_backend();
        // Neither key exists yet — should be rejected. v22.0.0
        // (CIRISPersist#543 / AV-76): the ATTESTER lookup is tier 2, the one
        // unavoidable directory read, so an unregistered attester is refused
        // there with the clearer-typed `InvalidArgument` — ahead of the tier-3
        // hybrid verify, which would only have reported the same key as
        // unresolvable in less specific words. This is the sqlite + postgres
        // answer too (both hoist the same lookup to tier 2 rather than let the
        // FK violation surface at INSERT); before the re-tiering memory alone
        // returned `FederationTierUnverified` here. Either way, no row stored.
        let att = fix_attestation("a-1", "registry-steward", "primitive-a", "registry-steward");
        let err = backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        // v54.1.0 (#1042) — typed as the retryable ordering gap now.
        assert!(
            matches!(&err, crate::federation::Error::AttesterKeyUnknown { attesting_key_id, plane: "attestation" }
                if attesting_key_id == "registry-steward"),
            "expected the tier-2 attester-lookup refusal, got {err:?}"
        );

        // Add the keys; retry succeeds.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("primitive-a", "primitive-a", "registry-steward"),
            })
            .await
            .unwrap();
        let att = fix_attestation("a-1", "registry-steward", "primitive-a", "registry-steward");
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap();
    }

    // ─── v22.0.0 (CIRISPersist#543) memory-backend parity witnesses ──
    //
    // Two gates sqlite + postgres both enforce were missing on the memory
    // backend. Memory is the backend every unit test reaches for first, so a
    // gate absent HERE is a gate the whole test suite proves nothing about —
    // the #518/#534/#536/#541 "tested on one backend, used on the other"
    // shape, arriving from the opposite direction.

    /// Fresh, well-formed Android-Strongbox hardware evidence (the shape the
    /// sqlite witnesses use, so the two backends are proven against the SAME
    /// artifact). `captured_at` is a parameter so the stale-nonce arm can
    /// reach back past `max_nonce_age`.
    fn strongbox_evidence(captured_at: chrono::DateTime<chrono::Utc>) -> serde_json::Value {
        serde_json::json!({
            "platform_attestation": {
                "Android": {
                    "key_attestation_chain": [
                        vec![0x30u8, 0x82, 0x01, 0x00],
                        vec![0x30u8, 0x82, 0x02, 0x00],
                    ],
                    "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                    "strongbox_backed": true,
                }
            },
            "nonce_captured_at": captured_at.to_rfc3339(),
        })
    }

    /// v22.0.0 (CIRISPersist#543) — WITNESS for hole 1: an `accord_holder`
    /// claim on the MEMORY backend is gated by the hardware-attestation
    /// policy, identically to sqlite (`sqlite_put_public_key_rejects_accord_
    /// holder_without_evidence` + siblings) and postgres.
    ///
    /// Before the fix `SqliteBackend::put_public_key` ran ZERO of this — the
    /// `hardware_attestation_policy` field did not exist on the backend — so
    /// an evidence-less `accord_holder`, the STRONGEST claim in the identity
    /// grammar (`ConferralMode::HardwareAttested`), was admitted for free.
    /// That is not a cosmetic gap: `check_privileged_identity_type_admission`
    /// deliberately DELEGATES `accord_holder` to this policy (it skips every
    /// non-`AccordCoScrubbed` mode), so with the policy absent nothing at all
    /// stood behind the claim, and a memory-backed node would seat a forged
    /// holder into the very roster the accord quorum is tallied from.
    ///
    /// All four policy outcomes are exercised, plus the two negative controls
    /// (non-holder needs no evidence; a rejected row leaves NO trace).
    #[tokio::test]
    async fn sqlite_put_public_key_gates_accord_holder_on_hardware_attestation_543() {
        use crate::federation::types::identity_type::ACCORD_HOLDER;
        let backend = test_backend();

        // (a) scalar `identity_type = accord_holder`, NO evidence → REJECT.
        let mut k = fix_key("mem-ah-no-ev", "humanity-accord-x", "mem-ah-no-ev");
        k.identity_type = ACCORD_HOLDER.into();
        k.attestation_evidence = None; // the leg under test: an unattested accord_holder
        let err = backend
            .put_public_key(SignedKeyRecord { record: k })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_accord_holder_requires_attestation_evidence",
            "evidence-less accord_holder must be refused on memory too, got {err:?}"
        );
        // …and verify-before-mutation: the refused row left no trace.
        assert!(
            FederationDirectory::lookup_public_key(&backend, "mem-ah-no-ev")
                .await
                .unwrap()
                .is_none(),
            "a refused accord_holder must not be stored"
        );

        // (b) #441 SET form ("agent,accord_holder") hits the same gate as the
        //     scalar — `claims_role`, not string equality.
        let mut k = fix_key("mem-ah-setform", "humanity-accord-x", "mem-ah-setform");
        k.identity_type = format!("agent,{ACCORD_HOLDER}");
        k.attestation_evidence = None; // the set-form claim, still unattested
        let err = backend
            .put_public_key(SignedKeyRecord { record: k })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_accord_holder_requires_attestation_evidence",
            "set-form accord_holder claim must hit the gate, got {err:?}"
        );

        // (c) #441 ROLES-vector form hits it too.
        let mut k = fix_key("mem-ah-roles", "humanity-accord-x", "mem-ah-roles");
        k.capability_roles = vec![ACCORD_HOLDER.to_string()];
        k.attestation_evidence = None; // the roles-vector claim, still unattested
        let err = backend
            .put_public_key(SignedKeyRecord { record: k })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_accord_holder_requires_attestation_evidence",
            "roles-vector accord_holder claim must hit the gate, got {err:?}"
        );

        // (d) the gate is the POLICY, not a presence check: a stale nonce is
        //     refused even though the evidence is structurally perfect.
        let stale = chrono::Utc::now() - chrono::Duration::days(30);
        let mut k = fix_key("mem-ah-stale", "humanity-accord-x", "mem-ah-stale");
        k.identity_type = ACCORD_HOLDER.into();
        k.attestation_evidence = Some(strongbox_evidence(stale));
        let err = backend
            .put_public_key(SignedKeyRecord { record: k })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_attestation_evidence_stale",
            "a months-old nonce must be refused on memory too, got {err:?}"
        );

        // (e) software-only custody is refused (the one structural floor
        //     Verify draws). Same evidence body as the sqlite twin.
        let mut k = fix_key("mem-ah-sw", "humanity-accord-x", "mem-ah-sw");
        k.identity_type = ACCORD_HOLDER.into();
        k.attestation_evidence = Some(serde_json::json!({
            "platform_attestation": {
                "Software": {
                    "key_derivation": "random",
                    "storage": "memory",
                    "security_warning": "test"
                }
            },
            "nonce_captured_at": chrono::Utc::now().to_rfc3339(),
        }));
        let err = backend
            .put_public_key(SignedKeyRecord { record: k })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_hardware_type_not_accepted",
            "SoftwareOnly custody must not seat an accord holder, got {err:?}"
        );

        // (f) POSITIVE control — fresh Strongbox evidence ADMITS. The gate
        //     tightens, it does not close the door on a real holder.
        let mut k = fix_key("mem-ah-ok", "humanity-accord-x", "mem-ah-ok");
        k.identity_type = ACCORD_HOLDER.into();
        k.attestation_evidence = Some(strongbox_evidence(chrono::Utc::now()));
        backend
            .put_public_key(SignedKeyRecord { record: k })
            .await
            .expect("a hardware-attested accord_holder must admit");
        let read = FederationDirectory::lookup_public_key(&backend, "mem-ah-ok")
            .await
            .unwrap()
            .expect("admitted holder is readable");
        assert_eq!(read.identity_type, ACCORD_HOLDER);

        // (g) NEGATIVE control — a non-holder still needs no evidence.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("mem-plain", "plain", "mem-plain"),
            })
            .await
            .expect("a non-accord_holder row must not require hardware evidence");
    }

    /// v22.0.0 (CIRISPersist#543) — WITNESS for hole 1's second half: the
    /// `validate_registration_pubkey` write-path invariant (#275) now runs on
    /// memory too. Before the fix a wrong-curve / wrong-length
    /// `pubkey_ed25519_base64` that sqlite and postgres BOTH refuse was
    /// admitted by memory, so the row a memory-backed test proved "registers
    /// fine" could not be replicated to either SQL backend.
    #[tokio::test]
    async fn sqlite_put_public_key_validates_registration_pubkey_543() {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        let backend = test_backend();
        // A 65-byte uncompressed P-256 point — the exact wrong-curve shape
        // the #275 saga produced. Not a 32-byte Ed25519 key.
        let mut k = fix_key("mem-badcurve", "badcurve", "mem-badcurve");
        k.pubkey_ed25519_base64 = BASE64.encode([0x04u8; 65]);
        let err = backend
            .put_public_key(SignedKeyRecord { record: k })
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::federation::Error::InvalidArgument(_)),
            "a 65-byte non-Ed25519 pubkey must be refused at admission, got {err:?}"
        );
        assert!(
            FederationDirectory::lookup_public_key(&backend, "mem-badcurve")
                .await
                .unwrap()
                .is_none(),
            "a refused malformed-pubkey row must not be stored"
        );
    }

    /// v22.0.0 (CIRISPersist#543) — WITNESS for hole 2: `put_attestation` on
    /// memory runs the closed-set `check_cohort_scope` VALUE gate, so an
    /// out-of-set `cohort_scope` fails with the SAME typed error sqlite
    /// (`sqlite.rs`) and postgres raise.
    ///
    /// Scope note, stated honestly: memory did not *store* a `global` row
    /// before this fix either — the AV-45 membership gate
    /// (`check_write_cohort_scope_for`) falls through to
    /// `ScopeRefusalReason::InvalidCohortScope` for any out-of-set value, so
    /// the ACCEPT/REJECT sets already matched. What did NOT match is the
    /// typed rejection: memory raised `WriteScopeRefused`
    /// (`federation_write_scope_refused`) where both SQL backends raise
    /// `CohortScopeRejected` (`federation_cohort_scope_rejected`) — and that
    /// kind string is the documented machine-readable contract consumers
    /// pattern-match on. A backend that refuses the right rows under the
    /// wrong error kind still breaks every caller that branches on the kind,
    /// which is why this asserts the kind and not merely `is_err()`.
    #[tokio::test]
    async fn sqlite_put_attestation_rejects_out_of_set_cohort_scope_543() {
        let backend = test_backend();
        for k in ["cs-attester", "cs-attested"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, k, k),
                })
                .await
                .unwrap();
        }

        // `global` is a §8.1.8 FEED name aggregating {species, biosphere,
        // federation} — never a wire value.
        let mut att = fix_attestation("cs-global", "cs-attester", "cs-attested", "cs-attester");
        att.cohort_scope = "global".to_string();
        crate::federation::tier_ingest::test_support::reseal(&mut att);
        let err = backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_cohort_scope_rejected",
            "memory must raise the same typed cohort_scope rejection as sqlite/postgres, got {err:?}"
        );
        assert!(
            backend
                .get_attestation("cs-global")
                .await
                .unwrap()
                .is_none(),
            "a refused cohort_scope row must leave no trace"
        );

        // Empty string — same closed-set refusal, same kind.
        let mut att = fix_attestation("cs-empty", "cs-attester", "cs-attested", "cs-attester");
        att.cohort_scope = String::new();
        crate::federation::tier_ingest::test_support::reseal(&mut att);
        let err = backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_cohort_scope_rejected",
            "an empty cohort_scope is out-of-set too, got {err:?}"
        );

        // POSITIVE control — every closed-set value that needs no membership
        // target still admits (the gate validates the VALUE, nothing more).
        // v47.0.0 (#897): `affiliations` needs one — it is a room.
        for (i, scope) in ["self", "species", "biosphere", "federation"]
            .into_iter()
            .enumerate()
        {
            let mut att = fix_attestation(
                &format!("cs-ok-{i}"),
                "cs-attester",
                "cs-attested",
                "cs-attester",
            );
            att.cohort_scope = scope.to_string();
            crate::federation::tier_ingest::test_support::reseal(&mut att);
            backend
                .put_attestation(SignedAttestation { attestation: att })
                .await
                .unwrap_or_else(|e| panic!("closed-set cohort_scope {scope} must admit: {e:?}"));
        }
    }

    /// v22.0.0 (CIRISPersist#543 finding 4) — WITNESS: the v3.4.0
    /// trust-weighted [`crate::federation::AdmissionGate`] now actually RUNS
    /// on the memory backend.
    ///
    /// `SqliteBackend` had no `admission_gate` field, no accessor and no
    /// call site, so `check_federation` had never executed on this backend
    /// on ANY write path since v3.4.0 — an installed gate was silently a
    /// no-op. Both directions are asserted: a below-threshold peer is
    /// REFUSED (`federation_trust_below_threshold`), and the same write
    /// from an above-threshold peer gets past the gate (it then fails
    /// further down the stack, which is the proof it was not stopped here).
    #[tokio::test]
    async fn admission_gate_is_wired_on_sqlite_543() {
        struct FixedTrustScoring(std::collections::HashMap<String, f64>);
        #[async_trait::async_trait]
        impl crate::federation::TrustScoring for FixedTrustScoring {
            async fn trust_score(
                &self,
                key_id: &str,
            ) -> Result<f64, crate::federation::TrustScoringError> {
                match self.0.get(key_id) {
                    Some(s) => Ok(*s),
                    None => Err(crate::federation::TrustScoringError::KeyNotFound(
                        key_id.into(),
                    )),
                }
            }
        }
        let gate_for = |pairs: &[(&str, f64)], threshold: f64| {
            let mut map = std::collections::HashMap::new();
            for (k, v) in pairs {
                map.insert((*k).to_owned(), *v);
            }
            crate::federation::AdmissionGate::new(
                std::sync::Arc::new(FixedTrustScoring(map)),
                threshold,
            )
        };

        // Default state: NO gate installed — bootstrap-permissive.
        let backend = test_backend();
        assert!(
            backend.admission_gate().is_none(),
            "a fresh memory backend must be bootstrap-permissive"
        );

        // Below threshold ⇒ the gate refuses, and it refuses FIRST: the
        // attesting key is not even registered, so any later gate would
        // have produced a different (more informative) error.
        backend.set_admission_gate(Some(gate_for(&[("ag-lo", 0.1)], 0.5)));
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation("ag-1", "ag-lo", "ag-lo", "ag-lo"),
            })
            .await
            .expect_err("a below-threshold peer must be refused");
        assert_eq!(
            err.kind(),
            "federation_trust_below_threshold",
            "the trust gate must run on memory and reject first — got {err:?}"
        );

        // Above threshold ⇒ NOT stopped here. The write still fails (the
        // key is unregistered), but on a LATER gate — which is what proves
        // the gate admitted rather than that it is inert.
        backend.set_admission_gate(Some(gate_for(&[("ag-hi", 0.9)], 0.5)));
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation("ag-2", "ag-hi", "ag-hi", "ag-hi"),
            })
            .await
            .expect_err("unregistered attester still fails downstream");
        assert_ne!(
            err.kind(),
            "federation_trust_below_threshold",
            "an above-threshold peer must pass the trust gate — got {err:?}"
        );

        // Clearing restores bootstrap-permissive.
        backend.set_admission_gate(None);
        assert!(backend.admission_gate().is_none(), "gate cleared");
    }

    #[tokio::test]
    async fn list_attestations_for_and_by() {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        let backend = test_backend();
        // Bootstrap: registry-steward, two primitives, three attestations.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-a", "primitive-a", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-b", "primitive-b", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation(
                    "att-1",
                    "registry-steward",
                    "k-a",
                    "registry-steward",
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation(
                    "att-2",
                    "registry-steward",
                    "k-b",
                    "registry-steward",
                ),
            })
            .await
            .unwrap();

        // Two attestations from registry-steward.
        let by = backend
            .all_attestations_by("registry-steward")
            .await
            .unwrap();
        assert_eq!(by.len(), 2);

        // One attestation FOR k-a.
        let for_a = backend.all_attestations_for("k-a").await.unwrap();
        assert_eq!(for_a.len(), 1);
        assert_eq!(for_a[0].attestation_id, "att-1");
    }

    /// v8.7.2 (#233 follow-on, CEG RC27 §11.10) — `subject_of_content`
    /// resolves the SIGNED subject set behind a content hash from the
    /// content-establishing `scores` attestation(s) binding it via
    /// `evidence_refs`. Memory-backend parity for the resolution.
    #[tokio::test]
    async fn subject_of_content_resolves_signed_subjects() {
        let backend = test_backend();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("producer", "producer", "registry-steward"),
            })
            .await
            .unwrap();
        let sha = "a".repeat(64);
        let other_sha = "b".repeat(64);

        // Establishing scores attestation binding `sha` with signed
        // subjects = [subj-1, subj-2].
        let mut est = fix_attestation("est-1", "producer", "producer", "registry-steward");
        est.attestation_envelope = serde_json::json!({
            "dimension": "content:established:v1",
            "evidence_refs": [sha],
        });
        resign_fix(&mut est); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        est.subject_key_ids = vec!["subj-1".into(), "subj-2".into()];
        resign_fix(&mut est); // #643 — a typed-column edit is a re-seal trigger
        backend
            .put_attestation(SignedAttestation { attestation: est })
            .await
            .unwrap();

        // Resolves the signed subjects for the bound hash.
        let subjects = crate::federation::admission::subject_of_content(&backend, &sha)
            .await
            .unwrap();
        assert_eq!(subjects.len(), 2);
        assert!(subjects.contains("subj-1") && subjects.contains("subj-2"));

        // A DIFFERENT (unbound) hash → empty (fail-secure).
        let none = crate::federation::admission::subject_of_content(&backend, &other_sha)
            .await
            .unwrap();
        assert!(none.is_empty());

        // A malformed (non-hex) hash → empty.
        let bad = crate::federation::admission::subject_of_content(&backend, "not-a-hash")
            .await
            .unwrap();
        assert!(bad.is_empty());
    }

    #[tokio::test]
    async fn attach_pqc_completes_hybrid_pending_key() {
        let backend = test_backend();
        // v31.0.0 (CIRISPersist#657) — a row the cold path can LEGITIMATELY
        // complete: self-scrubbed, with the ML-DSA pubkey bound into the signed
        // registration envelope. The old fixture attached the strings
        // "test-mldsa-pubkey" / "test-mldsa-sig" and passed, which is the defect
        // demonstrated in our own test suite.
        let (row, mldsa_pk, pqc_sig) =
            crate::federation::admission::pqc_attach_test_support::hybrid_pending_self_scrubbed(
                "k-pending",
                crate::federation::types::identity_type::PRIMITIVE,
            );
        backend
            .put_public_key(SignedKeyRecord { record: row })
            .await
            .unwrap();
        // Initially hybrid-pending.
        let row = FederationDirectory::lookup_public_key(&backend, "k-pending")
            .await
            .unwrap()
            .unwrap();
        assert!(row.is_pqc_pending());
        assert!(!row.is_pqc_complete());

        // Attach the PQC components.
        backend
            .attach_key_pqc_signature("k-pending", &mldsa_pk, &pqc_sig)
            .await
            .unwrap();

        let row = FederationDirectory::lookup_public_key(&backend, "k-pending")
            .await
            .unwrap()
            .unwrap();
        assert!(row.is_pqc_complete());
        assert_eq!(row.pubkey_ml_dsa_65_base64.as_deref(), Some(&*mldsa_pk));
        assert_eq!(row.scrub_signature_pqc.as_deref(), Some(&*pqc_sig));
        assert!(row.pqc_completed_at.is_some());
        // Hash recomputed.
        assert_eq!(row.persist_row_hash.len(), 64);
    }

    #[tokio::test]
    async fn attach_pqc_rejects_double_fill() {
        let backend = test_backend();
        let (row, mldsa_pk, pqc_sig) =
            crate::federation::admission::pqc_attach_test_support::hybrid_pending_self_scrubbed(
                "k-double",
                crate::federation::types::identity_type::PRIMITIVE,
            );
        backend
            .put_public_key(SignedKeyRecord { record: row })
            .await
            .unwrap();
        backend
            .attach_key_pqc_signature("k-double", &mldsa_pk, &pqc_sig)
            .await
            .unwrap();
        // Second attach errors with Conflict.
        let err = backend
            .attach_key_pqc_signature("k-double", &mldsa_pk, &pqc_sig)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::federation::Error::Conflict(_)));
    }

    #[tokio::test]
    async fn attach_pqc_rejects_missing_row() {
        let backend = test_backend();
        let err = backend
            .attach_key_pqc_signature("ghost", "mldsa-pk", "mldsa-sig")
            .await
            .unwrap_err();
        assert!(matches!(err, crate::federation::Error::InvalidArgument(_)));
    }

    // v30.8.0 (CIRISPersist#596 item 1) — gated with `grant_slash`, which needs
    // the conferral builder in `r2_test_support` (itself cfg(any(sqlite,
    // postgres)) because it requires a real signing path). A cfg on the helper
    // but not its CALL SITES is the v30.4.1 `_pyffi` defect exactly, and the
    // no-feature leg is what catches it. Coverage note: this test stops running
    // on the default build; its subject (revocation mechanics on the memory
    // backend) is covered on every featured leg.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    async fn attach_pqc_for_attestation_and_revocation() {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        let backend = test_backend();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("steward", "registry", "steward"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-target", "primitive-a", "steward"),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation("att-1", "steward", "k-target", "steward"),
            })
            .await
            .unwrap();
        backend
            .attach_attestation_pqc_signature("att-1", "att-pqc-sig")
            .await
            .unwrap();
        let atts = backend.all_attestations_for("k-target").await.unwrap();
        assert!(atts[0].is_pqc_complete());
        grant_slash(&backend, "steward").await;

        backend
            .put_revocation(SignedRevocation {
                revocation: fix_revocation("rev-1", "k-target", "steward", "steward"),
            })
            .await
            .unwrap();
        // v58.0.0 (CIRISPersist#991) — a revocation is hybrid at its door.
        let revs = backend.revocations_for("k-target").await.unwrap();
        assert!(revs[0].is_pqc_complete());
    }

    /// v0.3.2 (CIRISPersist#11) — list_hybrid_pending_* returns rows
    /// where pqc_completed_at IS NULL, oldest first; rows that have
    /// been hybrid-completed via attach_*_pqc_signature are excluded.
    /// This is the substrate `Engine.run_pqc_sweep` walks.
    #[tokio::test]
    async fn list_hybrid_pending_filters_completed_rows() {
        let backend = test_backend();
        // Steward + three agent keys.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("steward", "registry", "steward"),
            })
            .await
            .unwrap();
        // v31.0.0 (CIRISPersist#657) — `k-a` is the row this test COMPLETES, so
        // it is minted in the shape a legitimate cold-path fill-in has:
        // self-scrubbed, ML-DSA pubkey bound into the signed envelope. `k-b` /
        // `k-c` stay ordinary pending rows (never completed here).
        let (k_a, k_a_mldsa_pk, k_a_pqc_sig) =
            crate::federation::admission::pqc_attach_test_support::hybrid_pending_self_scrubbed(
                "k-a",
                crate::federation::types::identity_type::PRIMITIVE,
            );
        backend
            .put_public_key(SignedKeyRecord { record: k_a })
            .await
            .unwrap();
        for id in &["k-b", "k-c"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(id, "primitive", "steward"),
                })
                .await
                .unwrap();
        }
        // Two attestations, one revocation.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation("att-x", "steward", "k-a", "steward"),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation("att-y", "steward", "k-b", "steward"),
            })
            .await
            .unwrap();
        backend
            .put_revocation(SignedRevocation {
                revocation: // v30.8.0 (#596 item 1) — SELF-revocation: this test counts rows, and the
                // trust-root scaffolding a third-party conferral needs would
                // pollute the count it measures. Self-revocation needs no
                // authority and changes nothing else here.
                fix_revocation("rev-z", "steward", "steward", "steward"),
            })
            .await
            .unwrap();

        // All hybrid-pending — 4 keys (steward + 3 agents), 2 attestations, 1 revocation.
        let pending_keys = backend.list_hybrid_pending_keys(100).await.unwrap();
        let pending_atts = backend.list_hybrid_pending_attestations(100).await.unwrap();
        assert_eq!(pending_keys.len(), 4);
        assert_eq!(pending_atts.len(), 2);

        // Attach PQC to one row in each table. Filter excludes them.
        backend
            .attach_key_pqc_signature("k-a", &k_a_mldsa_pk, &k_a_pqc_sig)
            .await
            .unwrap();
        backend
            .attach_attestation_pqc_signature("att-x", "att-pqc-sig")
            .await
            .unwrap();
        let pending_keys = backend.list_hybrid_pending_keys(100).await.unwrap();
        let pending_atts = backend.list_hybrid_pending_attestations(100).await.unwrap();
        assert_eq!(pending_keys.len(), 3);
        assert!(!pending_keys.iter().any(|r| r.id == "k-a"));
        assert_eq!(pending_atts.len(), 1);
        assert_eq!(pending_atts[0].id, "att-y");
    }

    /// v0.3.2 (CIRISPersist#11) — limit caps the batch; envelope +
    /// classical_sig fields are populated correctly so the sweep can
    /// recompute the bound-signature input identical to the per-write
    /// cold-path.
    #[tokio::test]
    async fn list_hybrid_pending_limit_and_payload() {
        let backend = test_backend();
        for i in 0..5 {
            let id = format!("k-{i}");
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(&id, "primitive", &id),
                })
                .await
                .unwrap();
        }
        // Limit=2 returns 2 rows.
        let rows = backend.list_hybrid_pending_keys(2).await.unwrap();
        assert_eq!(rows.len(), 2);
        // Each row carries id, envelope, classical_sig — sufficient to
        // recompute the cold-path bound-signature input.
        for row in &rows {
            assert!(row.id.starts_with("k-"));
            assert!(!row.classical_sig_b64.is_empty());
            assert!(row.envelope.is_object());
        }
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
        crate::federation::hard_case::test_support::declare_node(&backend, "memory-test-node")
            .await;
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
        crate::federation::hard_case::test_support::declare_node(&backend, "memory-test-node")
            .await;
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
        crate::federation::hard_case::test_support::declare_node(&backend, "memory-test-node")
            .await;
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
        // Memory backend has no derived storage — nothing to tombstone.
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

    /// v0.2.1 — Backend::lookup_public_key dual-read. After
    /// put_public_key writes to federation_keys, the legacy
    /// Backend::lookup_public_key trait method (used by trace verify)
    /// reads back the same key via the federation table.
    #[tokio::test]
    async fn backend_lookup_public_key_dual_reads_federation() {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ed25519_dalek::SigningKey;
        let backend = test_backend();
        // Generate a real Ed25519 keypair so VerifyingKey parses.
        let signing = SigningKey::from_bytes(&[0xAB; 32]);
        let verifying = signing.verifying_key();
        let pk_b64 = B64.encode(verifying.to_bytes());

        // Write via federation surface only — no accord_public_keys insert.
        let mut rec = fix_key("agent-fed-1", "agent-1", "agent-fed-1");
        rec.pubkey_ed25519_base64 = pk_b64.clone();
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .unwrap();

        // Backend::lookup_public_key (legacy trait method, used by
        // trace verify) finds the key via federation_keys.
        let got = Backend::lookup_public_key(&backend, "agent-fed-1")
            .await
            .unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().to_bytes(), verifying.to_bytes());
    }

    /// v0.2.1 — When federation_keys has nothing, fall through to
    /// the legacy `accord_public_keys` map. This is the migration-
    /// window guarantee: trace verify keeps working against legacy
    /// rows while lens migrates.
    #[tokio::test]
    async fn backend_lookup_public_key_falls_back_to_legacy() {
        use ed25519_dalek::SigningKey;
        let backend = test_backend();
        let signing = SigningKey::from_bytes(&[0xCD; 32]);
        let verifying = signing.verifying_key();

        // Register via legacy add_public_key (mimics
        // accord_public_keys insert).
        backend.add_public_key("agent-legacy-1", verifying);

        let got = Backend::lookup_public_key(&backend, "agent-legacy-1")
            .await
            .unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().to_bytes(), verifying.to_bytes());

        // Unknown key → None (federation empty AND legacy empty).
        let none = Backend::lookup_public_key(&backend, "ghost").await.unwrap();
        assert!(none.is_none());
    }

    // v30.8.0 (CIRISPersist#596 item 1) — gated with `grant_slash`, which needs
    // the conferral builder in `r2_test_support` (itself cfg(any(sqlite,
    // postgres)) because it requires a real signing path). A cfg on the helper
    // but not its CALL SITES is the v30.4.1 `_pyffi` defect exactly, and the
    // no-feature leg is what catches it. Coverage note: this test stops running
    // on the default build; its subject (revocation mechanics on the memory
    // backend) is covered on every featured leg.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    async fn revocation_round_trip() {
        let backend = test_backend();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-bad", "primitive-bad", "registry-steward"),
            })
            .await
            .unwrap();
        grant_slash(&backend, "registry-steward").await;
        backend
            .put_revocation(SignedRevocation {
                revocation: fix_revocation(
                    "rev-1",
                    "k-bad",
                    "registry-steward",
                    "registry-steward",
                ),
            })
            .await
            .unwrap();
        let revs = backend.revocations_for("k-bad").await.unwrap();
        assert_eq!(revs.len(), 1);
        assert_eq!(revs[0].revocation_id, "rev-1");
        assert_eq!(revs[0].persist_row_hash.len(), 64);
    }

    // ─── v3.0.0 (CIRISPersist#116, CEG 0.2 §6.1) — structural-composer ──
    //     dedup (memory backend parity).

    fn fix_structural_composer(
        id: &str,
        attester: &str,
        ty: &str,
        references_attestation_id: &str,
        asserted_at: &str,
    ) -> Attestation {
        let mut row = Attestation {
            attestation_id: id.into(),
            attesting_key_id: attester.into(),
            attested_key_id: attester.into(),
            attestation_type: ty.into(),
            weight: None,
            asserted_at: asserted_at.parse().unwrap(),
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "references_attestation_id": references_attestation_id,
                "withdrawal_reason": "test",
            }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: attester.into(),
            scrub_timestamp: asserted_at.parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        resign_fix(&mut row); // v9.0.0 — sign the envelope (CC 5.3.2.4.3.1)
        row
    }

    #[tokio::test]
    async fn sqlite_put_attestation_structural_dedup_silent_noop() {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        let backend = test_backend();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        let w1 = fix_structural_composer(
            "w-1",
            "registry-steward",
            crate::federation::types::attestation_type::WITHDRAWS,
            "upstream-1",
            "2026-05-01T00:00:00Z",
        );
        let mut w2 = w1.clone();
        w2.attestation_id = "w-2".into();
        // v31.0.0 (CIRISPersist#598) — the LATER instant is what makes this a
        // replay rather than a byte-identical resend, so it is part of what the
        // seal must cover: set it BEFORE re-sealing, not after. Re-sealing
        // afterwards left the column at 05-02 and the signed twin at 05-01,
        // which is the exact divergence the instant-binding gate refuses.
        w2.asserted_at = "2026-05-02T00:00:00Z".parse().unwrap();
        crate::federation::tier_ingest::test_support::reseal(&mut w2);
        backend
            .put_attestation(SignedAttestation { attestation: w1 })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation { attestation: w2 })
            .await
            .unwrap();
        let rows = backend
            .all_attestations_for("registry-steward")
            .await
            .unwrap();
        let composers: Vec<_> = rows
            .iter()
            .filter(|r| r.attestation_type == crate::federation::types::attestation_type::WITHDRAWS)
            .collect();
        assert_eq!(composers.len(), 1, "second triple should be a no-op");
        assert_eq!(composers[0].attestation_id, "w-1");
    }

    // ── v6.4.0 (CIRISPersist#146 Ask 2, CEG §3.2.3 / §8.1.11.2) —
    // broadened `withdraws` admission gate on the memory backend
    // (parity with sqlite + postgres). The gate runs before the state
    // lock; this test confirms the rule numbers + the
    // independent-authority + the rule-3 delegation-chain path resolve
    // identically here.

    /// Build a memory-backend `withdraws` against `target_id`.
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

    /// v21.3.0 (CIRISPersist#510 P1) — the memory-backend leg of the
    /// closed consent-grammar admission gate (see
    /// `sqlite::tests::consent_grammar_admission_rejections_sqlite_510` /
    /// `postgres::tests::consent_grammar_admission_rejections_postgres_510`):
    /// an unknown restriction op, an unrecognized top-level payload
    /// field, and a non-consentable `kinds` entry each reject the WHOLE
    /// grant at `put_attestation`. Memory duplicates its own fixture
    /// helpers (`fix_key`/`fix_attestation`/`resign_fix`) rather than
    /// sharing `consent_grammar::test_support` (that module is
    /// feature-gated on sqlite/postgres so a no-backend build compiles
    /// cleanly — the same reason `consent_peer_set_folds_revocation_502e7`
    /// above doesn't share `consent_peer_set::test_support` either).
    #[tokio::test]
    async fn consent_grant_admission_rejects_closed_grammar_violations_510() {
        let backend = test_backend();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("node-510m", "node", "node-510m"),
            })
            .await
            .unwrap();

        fn bad_grant(id: &str, node: &str, payload: serde_json::Value) -> Attestation {
            let mut g = fix_attestation(id, node, node, node);
            g.attestation_envelope = serde_json::json!({
                "dimension": crate::federation::consent_peer_set::DIMENSION,
                "payload": payload,
            });
            g.subject_key_ids = vec![format!("peer-of-{node}")];
            resign_fix(&mut g); // envelope changed → re-sign (CC 5.3.2.4.3.1)
            g
        }

        fn expect_510_reject(
            result: &Result<crate::federation::AttestationOutcome, crate::federation::Error>,
            what: &str,
        ) {
            match result {
                Err(crate::federation::Error::InvalidArgument(msg)) => {
                    assert!(
                        msg.contains("#510"),
                        "{what} must reject with a #510-tagged reason, got: {msg}"
                    );
                }
                other => panic!("{what} must reject as InvalidArgument, got: {other:?}"),
            }
        }

        let bad1 = bad_grant(
            "510m-restr",
            "node-510m",
            serde_json::json!({
                "grants": "replication",
                "attestation_prefixes": ["trace:"],
                "restrictions": [{"op": "quantum_redaction"}],
            }),
        );
        let err1 = backend
            .put_attestation(SignedAttestation { attestation: bad1 })
            .await;
        expect_510_reject(&err1, "an unknown restriction op");

        let bad2 = bad_grant(
            "510m-field",
            "node-510m",
            serde_json::json!({
                "grants": "replication",
                "attestation_prefixes": ["trace:"],
                "unexpected_field_510": true,
            }),
        );
        let err2 = backend
            .put_attestation(SignedAttestation { attestation: bad2 })
            .await;
        expect_510_reject(&err2, "an unknown top-level payload field");

        let bad3 = bad_grant(
            "510m-kind",
            "node-510m",
            serde_json::json!({
                "grants": "replication",
                "attestation_prefixes": ["trace:"],
                "kinds": ["Key"],
            }),
        );
        let err3 = backend
            .put_attestation(SignedAttestation { attestation: bad3 })
            .await;
        expect_510_reject(&err3, "a non-consentable kind");
    }

    fn fix_delegates_to(
        id: &str,
        granter: &str,
        grantee: &str,
        scope: serde_json::Value,
    ) -> Attestation {
        let mut d = fix_attestation(id, granter, grantee, granter);
        d.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
        d.attestation_envelope = serde_json::json!({
            "references_attestation_id": id,
            "scope": scope,
        });
        resign_fix(&mut d); // envelope changed → re-sign (CC 5.3.2.4.3.1)
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

    /// v18.2.0 (CIRISPersist#481) — the pluggable-trust-root witnesses, all
    /// four asks through the REAL write + walk surfaces:
    /// 1. self-root `attestation(user → user)` ADMITS;
    /// 2. self-referential `delegates_to(root → root, scope:[infra:*])`
    ///    ADMITS (a root roots to itself) — and note the TWO-PLANES rule:
    ///    these are delegation SCOPE tokens in an envelope, not the
    ///    accord-conferred `infra:attest` key ROLE (which stays co-scrub
    ///    gated; see admission set-path tests);
    /// 3. `trust_root_valid` evaluates the full predicate (edge +
    ///    self-declaration + fresh heartbeat + halt latch);
    /// 4. the `withdraws` tombstone on the trust edge makes the walk treat
    ///    it as ABSENT (nuclear un-trust; base self-root untouched).
    #[tokio::test]
    async fn trust_root_walk_and_tombstone_481() {
        use crate::federation::trust_root::{trust_root_valid, TrustRootVerdict};
        let backend = test_backend();
        for (k, it) in [
            ("tr-user", "user"),
            ("tr-root", "node"),
            ("tr-la", "accord_holder"),
        ] {
            let mut rec = fix_key(k, "ref", k);
            rec.identity_type = it.to_owned();
            // v22.0.0 (CIRISPersist#543) — the memory backend now runs the
            // same `accord_holder` hardware gate sqlite/postgres do, so an
            // `accord_holder` fixture must carry real evidence. No-op for
            // every other identity_type.
            crate::federation::hardware_attestation::test_support::attach_hardware_evidence(
                &mut rec,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
        }

        // Ask 1 — the self-root base admits (attesting == attested == self).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation("tr-self", "tr-user", "tr-user", "tr-user"),
            })
            .await
            .expect("(1) self-root attestation(user→user) must admit");

        // Ask 2 — the self-referential root declaration admits.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_charter(
                    "tr-rootdecl",
                    "tr-root",
                    serde_json::json!(["infra:attest", "infra:serve"]),
                ),
            })
            .await
            .expect("(2) delegates_to(root→root, infra:*) must admit");

        // The user's trust edge.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_accepts(
                    "tr-edge",
                    "tr-user",
                    "tr-root",
                    serde_json::json!(["infra:attest", "infra:serve"]),
                ),
            })
            .await
            .expect("delegates_to(user→root) must admit");

        // Fresh heartbeat about the root (accord:* attester must be
        // an accord_holder — the constitutional asymmetry holds here too).
        let mut lc = fix_attestation("tr-lc", "tr-la", "tr-root", "tr-la");
        lc.attestation_envelope = serde_json::json!({
            "id": "tr-lc",
            "dimension": "accord:lifecycle:v1",
            "score": 1.0,
            "confidence": 0.9,
        });
        lc.asserted_at = chrono::Utc::now();
        resign_fix(&mut lc);
        backend
            .put_attestation(SignedAttestation { attestation: lc })
            .await
            .expect("the heartbeat from an accord_holder must admit");

        // Ask 3 — the walk: every leg green.
        let v: TrustRootVerdict = trust_root_valid(&backend, "tr-user", "tr-root")
            .await
            .expect("walk");
        assert!(v.edge_exists, "(3) live user→root edge");
        assert!(
            v.root_self_declares,
            "(3) root self-declares w/ infra scope"
        );
        assert_eq!(
            v.drill_freshness,
            crate::federation::trust_root::DrillFreshness::Green,
            "(3) fresh drill reads Green — reported, not gated on"
        );
        assert_ne!(v.halt_latched, Some(true), "(3) no halt latched");
        assert!(v.valid, "(3) all legs ⇒ valid");

        // A self-root is the immutable BASE, never a valid EXTERNAL root.
        let v0 = trust_root_valid(&backend, "tr-user", "tr-user")
            .await
            .expect("walk self");
        assert!(
            !v0.valid && !v0.edge_exists,
            "base self-root ≠ external root"
        );

        // Ask 4 — nuclear un-trust: withdraw the edge; the walk folds it
        // ABSENT. The base self-root is untouched (the app never bricks).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_withdraws("tr-w", "tr-user", "tr-edge"),
            })
            .await
            .expect("(4) withdraws on own edge must admit");
        let v2 = trust_root_valid(&backend, "tr-user", "tr-root")
            .await
            .expect("walk post-tombstone");
        assert!(!v2.edge_exists, "(4) tombstoned edge is ABSENT to the walk");
        assert!(!v2.valid, "(4) un-trust revokes validity");
        assert!(
            v2.root_self_declares
                && v2.drill_freshness == crate::federation::trust_root::DrillFreshness::Green,
            "(4) only the EDGE died — the root's own declarations stand"
        );
    }

    /// v23.0.0 (CIRISPersist#551 item 4, the REAL half) — **the drill is a
    /// trust SIGNAL, not a functionality gate.**
    ///
    /// A genesis root is valid until revoked, halted, or un-trusted:
    /// tombstones and the halt latch ARE the revocation mechanism, so a
    /// deadman on top of them gave the artifact a shelf life nobody intended
    /// — three months after the mint every node darkens together, with no
    /// error at the point of use. What the drill actually tells you is
    /// whether the root is GOVERNED or ABANDONED, and that is a thing to
    /// report, not a thing to withhold service over.
    ///
    /// So: `valid` no longer consults the drill at all, and the freshness
    /// rides a band — the same band-not-float discipline as every other
    /// score in the system. The hard gates (edge, charter, recovery, halt
    /// latch) are untouched: the kill switch and the operator's un-trust
    /// lever still work exactly as before.
    #[tokio::test]
    async fn drill_freshness_is_a_signal_not_a_gate_551() {
        use crate::federation::trust_root::{
            trust_root_valid, DrillFreshness, TRUST_ACCEPTS_DIMENSION, TRUST_CHARTER_DIMENSION,
        };
        let backend = test_backend();
        for (k, it) in [
            ("drill-user", "user"),
            ("drill-green", "node"),
            ("drill-yellow", "node"),
            ("drill-never", "node"),
            ("drill-la", "accord_holder"),
        ] {
            let mut rec = fix_key(k, "ref", k);
            rec.identity_type = it.to_owned();
            crate::federation::hardware_attestation::test_support::attach_hardware_evidence(
                &mut rec,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
        }
        let scope = || serde_json::json!(["infra:attest", "infra:serve"]);
        let stamp = |mut a: Attestation, dimension: &str| {
            a.attestation_envelope["dimension"] = serde_json::json!(dimension);
            resign_fix(&mut a);
            a
        };
        // A drill row about `root`, asserted `days_ago` days back.
        let drill = |id: &str, about: &str, days_ago: i64| {
            let mut d = fix_attestation(id, "drill-la", about, "drill-la");
            d.attestation_envelope = serde_json::json!({
                "id": id,
                "dimension": crate::federation::trust_root::ACCORD_HEARTBEAT_DIMENSION,
                "score": 1.0,
                "confidence": 0.9,
            });
            d.asserted_at = chrono::Utc::now() - chrono::Duration::days(days_ago);
            resign_fix(&mut d);
            d
        };
        // Stand up the HARD legs for each root: charter + the user's edge.
        for root in ["drill-green", "drill-yellow", "drill-never"] {
            for a in [
                stamp(
                    fix_charter(&format!("{root}-charter"), root, scope()),
                    TRUST_CHARTER_DIMENSION,
                ),
                stamp(
                    fix_delegates_to(&format!("{root}-edge"), "drill-user", root, scope()),
                    TRUST_ACCEPTS_DIMENSION,
                ),
            ] {
                backend
                    .put_attestation(SignedAttestation { attestation: a })
                    .await
                    .expect("hard legs admit");
            }
        }
        // Drills: fresh / aged into the yellow band / none at all.
        for a in [
            drill("dg-lc", "drill-green", 1),
            drill("dy-lc", "drill-yellow", 120),
        ] {
            backend
                .put_attestation(SignedAttestation { attestation: a })
                .await
                .expect("drill admits");
        }

        let green = trust_root_valid(&backend, "drill-user", "drill-green")
            .await
            .expect("walk");
        assert!(green.valid, "fresh drill + hard legs ⇒ valid: {green:?}");
        assert_eq!(green.drill_freshness, DrillFreshness::Green, "{green:?}");
        assert!(green.last_drill_at.is_some(), "the drill date is reported");

        // THE ASSERTION THIS TEST EXISTS FOR — a root drilled 120 days ago
        // still SERVES. Its trust card reads yellow; nothing is withheld.
        let yellow = trust_root_valid(&backend, "drill-user", "drill-yellow")
            .await
            .expect("walk");
        assert!(
            yellow.valid,
            "a stale-drilled root MUST still serve — the deadman is gone: {yellow:?}"
        );
        assert_eq!(yellow.drill_freshness, DrillFreshness::Yellow, "{yellow:?}");

        // Never drilled: valid, and RED. `last_drill_at: None` is what
        // distinguishes "never" from "long ago" — the band does not need a
        // fourth variant to say it.
        let never = trust_root_valid(&backend, "drill-user", "drill-never")
            .await
            .expect("walk");
        assert!(
            never.valid,
            "an undrilled root still serves — governance signal, not a gate: {never:?}"
        );
        assert_eq!(never.drill_freshness, DrillFreshness::Red, "{never:?}");
        assert_eq!(never.last_drill_at, None, "never drilled, and it says so");

        // The HARD gates are untouched: withdraw the one edge and trust
        // collapses, drill or no drill.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_withdraws("dg-w", "drill-user", "drill-green-edge"),
            })
            .await
            .expect("withdraws admits");
        let unrooted = trust_root_valid(&backend, "drill-user", "drill-green")
            .await
            .expect("walk");
        assert!(
            !unrooted.valid && !unrooted.edge_exists,
            "the un-trust lever still works: {unrooted:?}"
        );
        assert_eq!(
            unrooted.drill_freshness,
            DrillFreshness::Green,
            "…and the drill signal is reported independently of the gate"
        );
    }

    /// v23.0.0 (CIRISPersist#551 item 2) — the three `delegates_to` jobs are
    /// NAMED, and a mislabeled lever is refused.
    ///
    /// One wire type, three opposite jobs, discriminated only by direction:
    /// charter (R→R), conferral (R→subject), trust edge (node→R). #551 cost a
    /// session four wrong statements about the trust root, every one a "which
    /// `delegates_to` is this?" failure made while reading the source. So the
    /// job now rides the envelope `dimension`, and each predicate reads its
    /// own name instead of doing direction-arithmetic.
    ///
    /// Three properties, in the order that makes the design legible:
    /// 1. correctly-dimensioned rows walk exactly as before (PREFERRED);
    /// 2. an UNDIMENSIONED row still walks (direction-inference retained —
    ///    additive, no wire break, every pre-v23 row keeps working);
    /// 3. a row whose dimension CONTRADICTS its direction is REFUSED by the
    ///    predicate reading it. A mislabeled lever is worse than an
    ///    unlabeled one: unlabeled, the reader must look at direction and
    ///    gets it right; mislabeled, the label invites the reader to trust it.
    #[tokio::test]
    async fn trust_job_dimensions_named_and_contradictions_refused_551() {
        use crate::federation::trust_root::{
            trust_root_valid, TRUST_ACCEPTS_DIMENSION, TRUST_CHARTER_DIMENSION,
        };
        let backend = test_backend();
        for (k, it) in [
            ("d551-user", "user"),
            ("d551-root", "node"),
            ("d551-plain", "node"),
            ("d551-bad", "node"),
            ("d551-la", "accord_holder"),
        ] {
            let mut rec = fix_key(k, "ref", k);
            rec.identity_type = it.to_owned();
            crate::federation::hardware_attestation::test_support::attach_hardware_evidence(
                &mut rec,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
        }
        // A fresh liveness witness about `root`, so the other legs are green.
        let lifecycle = |id: &str, about: &str| {
            let mut lc = fix_attestation(id, "d551-la", about, "d551-la");
            lc.attestation_envelope = serde_json::json!({
                "id": id,
                "dimension": crate::federation::trust_root::ACCORD_HEARTBEAT_DIMENSION,
                "score": 1.0,
                "confidence": 0.9,
            });
            lc.asserted_at = chrono::Utc::now();
            resign_fix(&mut lc);
            lc
        };
        // Stamp a job dimension onto a row built by the shared fixtures.
        let stamp = |mut a: Attestation, dimension: &str| {
            a.attestation_envelope["dimension"] = serde_json::json!(dimension);
            resign_fix(&mut a);
            a
        };
        let scope = || serde_json::json!(["infra:attest", "infra:serve"]);

        // ── (1) CORRECTLY dimensioned: charter says charter, edge says
        //    accepts. Every leg green.
        for a in [
            stamp(
                fix_charter("d551-charter", "d551-root", scope()),
                TRUST_CHARTER_DIMENSION,
            ),
            stamp(
                fix_delegates_to("d551-edge", "d551-user", "d551-root", scope()),
                TRUST_ACCEPTS_DIMENSION,
            ),
            lifecycle("d551-lc", "d551-root"),
        ] {
            backend
                .put_attestation(SignedAttestation { attestation: a })
                .await
                .expect("(1) a job-dimensioned trust row must ADMIT — item 2 is additive");
        }
        let v = trust_root_valid(&backend, "d551-user", "d551-root")
            .await
            .expect("walk");
        assert!(
            v.edge_exists && v.root_self_declares && v.valid,
            "(1) correctly-named rows walk: {v:?}"
        );

        // ── (2) UNDIMENSIONED rows. #973 (CC 3.2 T4a): a NEW unlabelled row
        //    is no charter and gives no acceptance; the rows a node HELD when
        //    that rule arrived still walk by direction — no wire break and no
        //    re-signing for every row written before v23.0.0.
        let unlabelled = |mut a: Attestation| {
            a.attestation_envelope
                .as_object_mut()
                .unwrap()
                .remove("dimension");
            resign_fix(&mut a);
            a
        };
        for a in [
            unlabelled(fix_charter("d551-plaincharter", "d551-plain", scope())),
            fix_delegates_to("d551-plainedge", "d551-user", "d551-plain", scope()),
            lifecycle("d551-plainlc", "d551-plain"),
        ] {
            backend
                .put_attestation(SignedAttestation { attestation: a })
                .await
                .expect("(2) an undimensioned trust row admits as it always did");
        }
        let plain = trust_root_valid(&backend, "d551-user", "d551-plain")
            .await
            .expect("walk");
        assert!(
            !plain.edge_exists && !plain.root_self_declares && !plain.valid,
            "(2) a NEW unlabeled row is neither charter nor acceptance: {plain:?}"
        );
        for id in ["d551-plaincharter", "d551-plainedge"] {
            backend.mark_trust_direction_held(id);
        }
        let plain = trust_root_valid(&backend, "d551-user", "d551-plain")
            .await
            .expect("walk");
        assert!(
            plain.edge_exists && plain.root_self_declares && plain.valid,
            "(2) direction inference still decides a HELD unlabeled row: {plain:?}"
        );

        // ── (3) CONTRADICTION: same shapes, labels swapped. The charter
        //    (R→R) claims to be a trust edge; the edge (user→R) claims to be
        //    a charter. Neither predicate may accept the row that lies to it.
        for a in [
            stamp(
                fix_charter("d551-badcharter", "d551-bad", scope()),
                TRUST_ACCEPTS_DIMENSION,
            ),
            stamp(
                fix_delegates_to("d551-badedge", "d551-user", "d551-bad", scope()),
                TRUST_CHARTER_DIMENSION,
            ),
            lifecycle("d551-badlc", "d551-bad"),
        ] {
            backend
                .put_attestation(SignedAttestation { attestation: a })
                .await
                .expect("a mislabeled row still WRITES — refusal is the walk's job, not ingest's");
        }
        let bad = trust_root_valid(&backend, "d551-user", "d551-bad")
            .await
            .expect("walk");
        assert!(
            !bad.root_self_declares,
            "(3) a self-loop labeled `{TRUST_ACCEPTS_DIMENSION}` is NOT a charter: {bad:?}"
        );
        assert!(
            !bad.edge_exists,
            "(3) a user→root edge labeled `{TRUST_CHARTER_DIMENSION}` is NOT a trust edge: {bad:?}"
        );
        assert!(!bad.valid, "(3) a mislabeled lever confers nothing");
    }

    /// v19.1.0 (CIRISPersist#490) — THE acceptance witness: bake the REAL
    /// 2026-07-23 humanity-accord ceremony artifact (`genesis_v2.json`,
    /// byte-exact, sha256 44be2cf8…) against a node holding the REAL baked
    /// genesis state (A1/B1/C1 roster + the prior roles-less canonical
    /// anchor — the exact state that refused the adopt in the field).
    ///
    /// Proves end-to-end, with production cryptography:
    /// 1. the bundle quorum (A1+B1 hybrid YubiKey authorizations) verifies
    ///    against persist's OWN roster + directory-pinned keys;
    /// 2. the anchored-but-different canonical is RE-ANCHORED (the exact
    ///    "downgrade/replace refused" case, now authenticated);
    /// 3. the #486 lift makes the re-blessed record claim `infra:serve`
    ///    (envelope-attested, top-level `roles:[]` on the wire);
    /// 4. the delegation plane admits (the charter passes the v19.0.0
    ///    pre-rotation gate; the serve grant lands);
    /// 5. re-baking the same artifact is a no-op (idempotent).
    #[tokio::test]
    async fn bake_real_genesis_v2_artifact_490() {
        use crate::federation::genesis::{bake_assembled_genesis, BakeItemOutcome};
        let backend = test_backend();

        // Seed the REAL baked genesis state: the A1/B1/C1 holder roster…
        // v22.0.0 (CIRISPersist#543) — through `seed_genesis_accord_holders`,
        // the same door the sqlite + postgres genesis paths use, NOT bare
        // `put_public_key`. The baked ceremony evidence is a #268 custody
        // attestation with a stale-by-design nonce; re-checking it at every
        // boot is a category error, which is exactly why the SQL backends
        // have a dedicated seed entry point. Memory reaching for
        // `put_public_key` here was the tell that it had no hardware gate to
        // need seeding around.
        backend
            .seed_genesis_accord_holders(
                &crate::federation::genesis::effective_accord_holder_records(),
            )
            .await
            .expect("seed accord holder roster");
        // …and the PRIOR canonical anchor — the PRE-CEREMONY roles-less
        // record (kept as a fixture: the live baked seed is now the
        // re-blessed one, so the field-refusal state must be seeded
        // explicitly).
        let prev: Vec<crate::federation::SignedKeyRecord> =
            serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/canonical_seed_pre_ceremony.json"
            )))
            .expect("pre-ceremony seed fixture parses");
        for rec in prev {
            backend
                .put_public_key(rec)
                .await
                .expect("seed prior canonical anchor");
        }
        let canon = "ciris-canonical-1-d7bdeu223k";
        let before = crate::federation::FederationDirectory::lookup_public_key(&backend, canon)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !before.claims_role("infra:serve"),
            "fixture: prior anchor is dark (no infra:serve) — the #480 state"
        );

        // v31.2.0 (CIRISPersist#660) — seed the constitutional family before
        // baking. The re-minted ceremony's `genesis-charter` attests TO
        // `humanity-accord`, so the delegation plane cannot land against a node
        // that has never heard of the family: `put_attestation` refuses with
        // "attested_key_id humanity-accord resolves as neither a registered
        // federation_keys row nor a constitutional family known to this node".
        // The #557 dry-run test already seeded it in the same order; this arm
        // was relying on the old fixture's shape.
        crate::federation::genesis::seed_accord_family(&backend)
            .await
            .expect("seed the constitutional family");

        // Bake the REAL artifact.
        let artifact = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/genesis_v2.json"
        ));
        let report = bake_assembled_genesis(&backend, artifact)
            .await
            .expect("the real ceremony artifact must verify and bake");
        assert_eq!(
            report.quorum_verified, 2,
            "A1+B1 hybrid authorizations verified"
        );
        assert_eq!(
            report.serve_nodes,
            vec![(canon.to_owned(), BakeItemOutcome::ReAnchored)],
            "the anchored-but-different canonical is re-anchored under quorum"
        );
        // v31.0.0 (CIRISPersist#648) — the delegation plane is regime-branched
        // on the ARTIFACT, not on an edited expectation.
        //
        // `genesis_v2.json` is the REAL 2026-07-23 ceremony artifact and it was
        // signed before the #643 row mirror existed, so its delegation rows
        // carry no signed `row` object and `put_attestation` refuses them. That
        // gate closes the verb-substitution and authority-injection attacks and
        // is not weakened here: a genesis-shaped carve-out would be a permanent
        // hole in exactly the rows that grant everything.
        //
        // The KEY plane above is untouched and still proves the whole #490
        // acceptance story (quorum verifies, the anchored-but-different
        // canonical re-anchors under quorum, the #486 lift opens the trace
        // plane). What the delegation half asserts now is the truth of a
        // pre-v31 build: every row is SKIPPED, naming #643. When the same
        // holders re-sign under the new envelope shape for 31.1.0, this flips
        // back to `Anchored` by itself.
        let artifact_bundle: crate::federation::genesis::GenesisBundle =
            serde_json::from_str(artifact).expect("artifact parses");
        let row_bound =
            crate::federation::genesis::bundle_delegation_plane_v31_shaped(&artifact_bundle);
        for (id, outcome) in &report.attestations {
            match &row_bound {
                Ok(()) => assert!(
                    matches!(
                        outcome,
                        BakeItemOutcome::Anchored | BakeItemOutcome::AlreadyPresent
                    ),
                    "delegation-plane row {id} must land, got {outcome:?}"
                ),
                Err(_) => match outcome {
                    BakeItemOutcome::Skipped(why) => assert!(
                        crate::federation::genesis::is_v31_binding_refusal(why),
                        "row {id} must be skipped BY THE BINDING GATE, not for some other \
                         reason: {why}"
                    ),
                    other => panic!(
                        "a pre-v31 delegation row {id} must be refused by the #643 gate, \
                         got {other:?} — the gate has a hole"
                    ),
                },
            }
        }

        // The mesh is bright: the re-blessed record claims infra:serve
        // (the #486 lift over the envelope-attested set).
        let after = crate::federation::FederationDirectory::lookup_public_key(&backend, canon)
            .await
            .unwrap()
            .unwrap();
        assert!(after.claims_role("infra:serve"), "the trace plane opens");
        assert!(after.claims_role(crate::federation::types::identity_type::CANONICAL));
        assert!(
            after.valid_from > before.valid_from,
            "anti-rollback ordering"
        );

        // Idempotent: same artifact again → nothing changes, no error.
        let again = bake_assembled_genesis(&backend, artifact)
            .await
            .expect("re-bake is a no-op, not an error");
        assert_eq!(
            again.serve_nodes,
            vec![(canon.to_owned(), BakeItemOutcome::AlreadyPresent)],
            "idempotent re-bake"
        );

        // A tampered bundle (flipped byte in an authorization) refuses and
        // writes NOTHING.
        let mut tampered: serde_json::Value = serde_json::from_str(artifact).unwrap();
        tampered["authorizations"][0]["signature_classical"] = serde_json::json!("QUFBQQ==");
        let err = bake_assembled_genesis(&backend, &tampered.to_string())
            .await
            .expect_err("tampered authorization must refuse");
        assert_eq!(err.kind(), "federation_genesis_bundle_invalid");
    }

    /// v21.0.0 (CIRISPersist#502 E9) — the operational role authority
    /// resolves the steward roster from OUR OWN registered directory, not a
    /// caller-passed slice. A grant rooted at a key that is NOT a registered
    /// steward is REFUSED — a caller can no longer bless itself by handing
    /// in a roster.
    #[tokio::test]
    async fn operational_roster_resolves_from_own_directory_502e9() {
        use crate::federation::operational::test_support as op;
        let backend = test_backend();
        let steward = op::Identity::new("e9-steward");
        let admin = op::Identity::new("e9-admin");

        // v31.0.0 (CIRISPersist#644) — the outsider is now REGISTERED (as a
        // plain agent), which sharpens this test rather than weakening it.
        // Before #644 the first leg refused a key the directory had never
        // heard of, so "not a steward" and "not registered at all" were
        // indistinguishable — and the row's own signature was never checked,
        // so the leg could not have told them apart. Now the outsider's
        // signature VERIFIES and the ONLY thing it lacks is steward status,
        // which is precisely the E9 property under test.
        let outsider = op::Identity::new("e9-outsider");
        crate::federation::tier_ingest::test_support::register_hybrid_key(&backend, "e9-outsider")
            .await;

        // Grant rooted at a registered NON-steward → the resolved roster
        // does not contain it → NoQualifyingGrant, refused.
        let grant = op::signed_membership(
            "e9-m1",
            &outsider,
            "e9-admin",
            "e9-org",
            "org_admin",
            "active",
            chrono::Utc::now(),
        );
        let err = backend
            .put_org_membership(grant)
            .await
            .expect_err("(E9) grant rooted at a non-steward is refused");
        assert!(
            err.kind().contains("operational_authority"),
            "kind {}",
            err.kind()
        );

        // Register the steward IN OUR DIRECTORY → now the same grant admits.
        backend
            .put_public_key(SignedKeyRecord {
                record: steward.steward_key_record(),
            })
            .await
            .expect("register steward");
        let grant2 = op::signed_membership(
            "e9-m2",
            &steward,
            "e9-admin",
            "e9-org",
            "org_admin",
            "active",
            chrono::Utc::now(),
        );
        backend
            .put_org_membership(grant2)
            .await
            .expect("(E9) grant rooted at a REGISTERED steward admits");
        let _ = &admin;
    }

    // v30.8.0 (CIRISPersist#596 item 1) — gated with `grant_slash`, which needs
    // the conferral builder in `r2_test_support` (itself cfg(any(sqlite,
    // postgres)) because it requires a real signing path). A cfg on the helper
    // but not its CALL SITES is the v30.4.1 `_pyffi` defect exactly, and the
    // no-feature leg is what catches it. Coverage note: this test stops running
    // on the default build; its subject (revocation mechanics on the memory
    // backend) is covered on every featured leg.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    /// v21.0.0 (CIRISPersist#502 E1) — a forged revocation (scrub sig by a
    /// key OTHER than the declared revoking key) is REJECTED. The attack:
    /// any linked peer forging `{revoked: victim, revoking: any-existing}`
    /// for a targeted de-peer. Before this it admitted on FK-existence.
    #[tokio::test]
    async fn forged_revocation_wrong_signer_rejected_502e1() {
        let backend = test_backend();
        for k in ["e1-victim", "e1-revoker", "e1-attacker"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "ref", k),
                })
                .await
                .unwrap();
        }
        // Honest revocation (revoker signs) — admits.
        let good = fix_revocation("e1-good", "e1-victim", "e1-revoker", "e1-revoker");
        grant_slash(&backend, "e1-revoker").await;
        backend
            .put_revocation(crate::federation::SignedRevocation { revocation: good })
            .await
            .expect("(E1) honestly-signed revocation admits");

        // Forged: claims revoking=e1-revoker but the envelope is signed by
        // the ATTACKER's key. The registered pubkeys of e1-revoker won't
        // verify it → reject.
        let mut forged = fix_revocation("e1-forged", "e1-victim", "e1-revoker", "e1-revoker");
        let (och, sc, sp) = crate::federation::tier_ingest::test_support::sign_envelope(
            "e1-attacker",
            &forged.revocation_envelope,
        );
        forged.original_content_hash = och;
        forged.scrub_signature_classical = sc;
        forged.scrub_signature_pqc = sp;
        let err = backend
            .put_revocation(crate::federation::SignedRevocation { revocation: forged })
            .await
            .expect_err("(E1) forged revocation must be rejected");
        assert!(
            err.kind().contains("federation_tier_unverified") || err.kind().contains("unverified"),
            "rejected by hybrid verify, got kind {}",
            err.kind()
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
            let mut rec = fix_key(k, "ref", k);
            rec.identity_type = it.to_owned();
            // v22.0.0 (CIRISPersist#543) — the memory backend now runs the
            // same `accord_holder` hardware gate sqlite/postgres do, so an
            // `accord_holder` fixture must carry real evidence. No-op for
            // every other identity_type.
            crate::federation::hardware_attestation::test_support::attach_hardware_evidence(
                &mut rec,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
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
        backend
            .put_attestation(SignedAttestation {
                attestation: charter,
            })
            .await
            .unwrap();

        let mut edge = fix_delegates_to(
            "e5-e",
            "e5-user",
            "e5-root",
            serde_json::json!(["infra:serve"]),
        );
        edge.tier = crate::federation::types::attestation_tier::LOCAL.to_string();
        resign_fix(&mut edge);
        backend
            .put_attestation(SignedAttestation { attestation: edge })
            .await
            .unwrap();

        let mut lc = fix_attestation("e5-lc", "e5-la", "e5-root", "e5-la");
        lc.attestation_envelope = serde_json::json!({
            "id": "e5-lc", "dimension": "accord:lifecycle:v1", "score": 1.0, "confidence": 0.9,
        });
        lc.asserted_at = chrono::Utc::now();
        lc.tier = crate::federation::types::attestation_tier::LOCAL.to_string();
        resign_fix(&mut lc);
        backend
            .put_attestation(SignedAttestation { attestation: lc })
            .await
            .unwrap();

        let v = trust_root_valid(&backend, "e5-user", "e5-root")
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
    /// serve-only self-loop is not a root; (3) an EXPIRED trust edge is as
    /// dead to the walk as a tombstoned one.
    #[tokio::test]
    async fn rc3_charter_deltas_488() {
        use crate::federation::trust_root::{test_pre_rotation_commitment, trust_root_valid};
        let backend = test_backend();
        for (k, it) in [
            ("rc-user", "user"),
            ("rc-root", "node"),
            ("rc-root2", "node"),
        ] {
            let mut rec = fix_key(k, "ref", k);
            rec.identity_type = it.to_owned();
            // v22.0.0 (CIRISPersist#543) — the memory backend now runs the
            // same `accord_holder` hardware gate sqlite/postgres do, so an
            // `accord_holder` fixture must carry real evidence. No-op for
            // every other identity_type.
            crate::federation::hardware_attestation::test_support::attach_hardware_evidence(
                &mut rec,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
        }

        // (1) commitment-less charter REFUSES with the typed kind.
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "rc-bare",
                    "rc-root",
                    "rc-root",
                    serde_json::json!(["infra:serve", "infra:attest"]),
                ),
            })
            .await
            .expect_err("(1) charter without pre-rotation commitment must refuse");
        assert_eq!(err.kind(), "federation_charter_invalid");

        // (2) serve-only charter admits (it is a valid delegates_to) but is
        // NOT a root to the walk — the AND-minimum.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_charter(
                    "rc-serveonly",
                    "rc-root2",
                    serde_json::json!(["infra:serve"]),
                ),
            })
            .await
            .expect("serve-only self-loop admits (charter-shaped, commitment present)");
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_accepts(
                    "rc-edge2",
                    "rc-user",
                    "rc-root2",
                    serde_json::json!(["infra:serve"]),
                ),
            })
            .await
            .unwrap();
        let v = trust_root_valid(&backend, "rc-user", "rc-root2")
            .await
            .unwrap();
        assert!(v.edge_exists);
        assert!(
            !v.root_self_declares && !v.valid,
            "(2) serve-only self-loop is NOT a root (serve∧attest minimum)"
        );

        // (3) an expired edge is dead to the walk.
        let mut expired = fix_delegates_to(
            "rc-expired-edge",
            "rc-user",
            "rc-root",
            serde_json::json!(["infra:serve"]),
        );
        expired.expires_at = Some(chrono::Utc::now() - chrono::Duration::hours(1));
        resign_fix(&mut expired);
        backend
            .put_attestation(SignedAttestation {
                attestation: expired,
            })
            .await
            .unwrap();
        let v3 = trust_root_valid(&backend, "rc-user", "rc-root")
            .await
            .unwrap();
        assert!(
            !v3.edge_exists,
            "(3) expired delegates_to is ABSENT to the walk"
        );

        // (1b) recovery binding: predecessor charter pre-commits to a
        // successor set; the bound successor charter ADMITS; a non-binding
        // one REFUSES; a non-member attester REFUSES.
        let successors = vec!["rc-root2".to_owned(), "rc-user".to_owned()];
        let commitment = test_pre_rotation_commitment(&successors).unwrap();
        let mut pred = fix_delegates_to(
            "rc-pred",
            "rc-root",
            "rc-root",
            serde_json::json!(["infra:serve", "infra:attest"]),
        );
        pred.attestation_envelope = serde_json::json!({
            "references_attestation_id": "rc-pred",
            "scope": ["infra:serve", "infra:attest"],
            "pre_rotation_commitment": commitment,
        });
        resign_fix(&mut pred);
        backend
            .put_attestation(SignedAttestation { attestation: pred })
            .await
            .expect("predecessor charter admits");

        // Bound successor charter: attester rc-root2 ∈ pre-committed set.
        let mut succ = fix_charter(
            "rc-succ",
            "rc-root2",
            serde_json::json!(["infra:serve", "infra:attest"]),
        );
        let succ_env = serde_json::json!({
            "references_attestation_id": "rc-succ",
            "scope": ["infra:serve", "infra:attest"],
            "pre_rotation_commitment":
                test_pre_rotation_commitment(&["rc-next-a".to_owned()]).unwrap(),
            "recovers": "rc-root",
            "successor_keys": successors,
        });
        succ.attestation_envelope = succ_env;
        resign_fix(&mut succ);
        backend
            .put_attestation(SignedAttestation {
                attestation: succ.clone(),
            })
            .await
            .expect("(1b) BOUND recovery charter admits");

        // Non-binding successor set → refused.
        let mut bad = succ.clone();
        bad.attestation_id = "rc-succ-bad".into();
        bad.attestation_envelope["successor_keys"] =
            serde_json::json!(["rc-root2", "not-precommitted"]);
        resign_fix(&mut bad);
        let err = backend
            .put_attestation(SignedAttestation { attestation: bad })
            .await
            .expect_err("(1b) non-binding successor set must refuse");
        assert_eq!(err.kind(), "federation_charter_invalid");
    }

    /// v19.0.0 (CIRISPersist#486) — envelope-attested roles LIFT into the
    /// claim surface (union, then gate): a scrub-signed envelope carrying
    /// `roles:["infra:serve"]` becomes visible to `claims_role` after
    /// `put_public_key`; a GATED role (`infra:attest`) lifted from an
    /// envelope with no accord co-scrub still REFUSES at its write gate —
    /// lifting creates visibility, never conferral.
    #[tokio::test]
    async fn envelope_attested_roles_lift_then_gate_486() {
        let backend = test_backend();
        // v31.0.0 (CIRISPersist#648) — seat the accord roster so the refusal
        // below comes from the `infra:attest` CONFERRAL gate rather than from
        // the empty-roster accident this fixture used to rely on. Plain `node`
        // rows under the roster key_ids resolve without being able to confer
        // anything. See `run_set_path_parity` for the same correction.
        for kid in crate::federation::genesis::effective_accord_holder_records().iter() {
            let mut seat = fix_key(&kid.record.key_id, "ref", &kid.record.key_id);
            seat.identity_type = "node".to_owned();
            let _ = backend
                .put_public_key(SignedKeyRecord { record: seat })
                .await;
        }

        // Ungated role in the envelope, empty top-level roles (the exact
        // #480 shape): after put, the row CLAIMS infra:serve.
        let mut rec = fix_key("lift-1", "ref", "lift-1");
        rec.identity_type = "node".to_owned();
        rec.registration_envelope = serde_json::json!({
            "key_id": "lift-1",
            "roles": ["infra:serve"],
        });
        assert!(
            rec.capability_roles.is_empty(),
            "fixture: top-level roles empty"
        );
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("envelope-roled record admits");
        let row = crate::federation::FederationDirectory::lookup_public_key(&backend, "lift-1")
            .await
            .unwrap()
            .unwrap();
        assert!(
            row.claims_role("infra:serve"),
            "(486) envelope-attested infra:serve is VISIBLE to claims_role"
        );

        // Lift-then-gate: infra:attest in the envelope of a record with NO
        // accord co-scrub → the v15 write gate refuses the lifted claim.
        let mut gated = fix_key("lift-2", "ref", "lift-2");
        gated.identity_type = "node".to_owned();
        gated.registration_envelope = serde_json::json!({
            "key_id": "lift-2",
            "roles": ["infra:attest"],
        });
        let err = backend
            .put_public_key(SignedKeyRecord { record: gated })
            .await
            .expect_err("(486) lifted infra:attest with no co-scrub must refuse");
        assert!(
            err.kind().contains("infra_attest") || err.kind().contains("accord"),
            "refused by the infra:attest gate, got kind {}",
            err.kind()
        );
    }

    /// v18.3.0 (CIRISPersist#483) — the composed capability walk: a
    /// subject's `infra:serve`, granted by a root the asking user trusts,
    /// resolves to that root; when the user un-trusts the root (edge
    /// tombstone), the SAME subject grant no longer roots → `None`. This is
    /// edge#386's trace-serve gate: serve only under a COMMON valid root.
    #[tokio::test]
    async fn capability_roots_to_trusted_root_483() {
        use crate::federation::trust_root::{capability_roots_to_trusted_root, trust_root_valid};
        let backend = test_backend();
        for (k, it) in [
            ("cr-user", "user"),
            ("cr-root", "node"),
            ("cr-peer", "node"),
            ("cr-la", "accord_holder"),
        ] {
            let mut rec = fix_key(k, "ref", k);
            rec.identity_type = it.to_owned();
            // v22.0.0 (CIRISPersist#543) — the memory backend now runs the
            // same `accord_holder` hardware gate sqlite/postgres do, so an
            // `accord_holder` fixture must carry real evidence. No-op for
            // every other identity_type.
            crate::federation::hardware_attestation::test_support::attach_hardware_evidence(
                &mut rec,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
        }
        let infra = || serde_json::json!(["infra:attest", "infra:serve"]);

        // Root self-declares + user trusts it + fresh lifecycle (the full
        // valid-root fixture, mirroring the 481 witness).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_charter("cr-rootdecl", "cr-root", infra()),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_accepts("cr-edge", "cr-user", "cr-root", infra()),
            })
            .await
            .unwrap();
        let mut lc = fix_attestation("cr-lc", "cr-la", "cr-root", "cr-la");
        lc.attestation_envelope = serde_json::json!({
            "id": "cr-lc", "dimension": "accord:lifecycle:v1", "score": 1.0, "confidence": 0.9,
        });
        lc.asserted_at = chrono::Utc::now();
        resign_fix(&mut lc);
        backend
            .put_attestation(SignedAttestation { attestation: lc })
            .await
            .unwrap();
        assert!(
            trust_root_valid(&backend, "cr-user", "cr-root")
                .await
                .unwrap()
                .valid,
            "fixture: root is valid for the user"
        );

        // The root grants the PEER infra:serve.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "cr-grant",
                    "cr-root",
                    "cr-peer",
                    serde_json::json!(["infra:serve"]),
                ),
            })
            .await
            .unwrap();

        // #483 — the peer's infra:serve roots to a root the user trusts.
        let grant = capability_roots_to_trusted_root(&backend, "cr-user", "cr-peer", "infra:serve")
            .await
            .expect("walk")
            .expect("peer serves under a root the user trusts");
        assert_eq!(grant.root_key_id, "cr-root");
        assert_eq!(grant.grant_attestation_id, "cr-grant");
        assert!(grant.verdict.valid);

        // A scope the peer was NOT granted → None.
        assert!(
            capability_roots_to_trusted_root(&backend, "cr-user", "cr-peer", "infra:store")
                .await
                .unwrap()
                .is_none(),
            "ungranted scope roots nowhere"
        );

        // Un-trust the root: the peer's grant now roots to nothing.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_withdraws("cr-w", "cr-user", "cr-edge"),
            })
            .await
            .unwrap();
        assert!(
            capability_roots_to_trusted_root(&backend, "cr-user", "cr-peer", "infra:serve")
                .await
                .unwrap()
                .is_none(),
            "un-trusting the root stops the peer serving immediately (edge#386)"
        );
    }

    /// v18.3.0 (CIRISPersist#484) — the exported co-scrub minting helpers
    /// let a consumer test the `has_accord_conferred_role` ALLOW path, not just the
    /// deny path (the CIRISEdge#379 fail-closed-blindness fix). Same crate,
    /// so `#[cfg(test)]` reaches them; downstream reaches them via the
    /// `test-anchor` feature (`ciris_persist::federation::accord_test_support`).
    #[tokio::test]
    async fn exported_coscrub_helpers_prove_has_accord_conferred_role_allow_and_deny_484() {
        use crate::federation::admission::has_accord_conferred_role_over_roster;
        use crate::federation::operational::test_support::{
            register_accord_holder, signed_canonical_record, signed_canonical_record_with_roles,
            Identity, PLACEHOLDER_SUBJECT_ED25519_BASE64,
        };
        let backend = test_backend();

        // A 2-of-3 accord family (register the pinned pubkeys the co-scrub
        // verifies against).
        let holders = [
            Identity::new("h0-484"),
            Identity::new("h1-484"),
            Identity::new("h2-484"),
        ];
        for h in &holders {
            register_accord_holder(&backend, h)
                .await
                .expect("register holder");
        }
        let roster: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();
        let env = serde_json::json!({ "key_id": "canon-484", "purpose": "test" });

        // ALLOW: a genuinely co-scrubbed record claiming infra:serve, signed
        // by 2 distinct holders → has_accord_conferred_role == true.
        let allow = signed_canonical_record_with_roles(
            "canon-484",
            "node",
            PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            vec!["infra:serve".to_owned()],
            env.clone(),
            &[&holders[0], &holders[1]],
        );
        backend
            .put_public_key(SignedKeyRecord { record: allow })
            .await
            .expect("co-scrubbed record admits");
        assert!(
            has_accord_conferred_role_over_roster(&backend, "canon-484", "infra:serve", &roster)
                .await
                .unwrap(),
            "(484) genuinely co-scrubbed record → has_accord_conferred_role ALLOW"
        );

        // DENY: a record with the SAME role claim but NO co-scrub (only a
        // self-scrub) → false. This is what edge could test before; now both
        // arms are provable.
        let self_only = signed_canonical_record_with_roles(
            "canon-484-self",
            "node",
            PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            vec!["infra:serve".to_owned()],
            serde_json::json!({ "key_id": "canon-484-self" }),
            &[&Identity::new("self-484")], // not in the roster → does not count
        );
        backend
            .put_public_key(SignedKeyRecord { record: self_only })
            .await
            .expect("self-scrubbed record still stores");
        assert!(
            !has_accord_conferred_role_over_roster(
                &backend,
                "canon-484-self",
                "infra:serve",
                &roster
            )
            .await
            .unwrap(),
            "(484) self-asserted role with no accord co-scrub → DENY"
        );

        // And the plain (rolesless) builder is unaffected — sanity that the
        // export didn't change existing behavior.
        let _plain = signed_canonical_record(
            "x-484",
            "node",
            PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            env,
            &[&holders[0]],
        );
    }

    /// v18.3.0 (CIRISPersist#480, persist-side compat confirmation) — a
    /// `canonical,node` record that ALSO carries `roles:["infra:serve"]`
    /// still (a) passes the 2-of-3 `check_canonical_role_admission` core
    /// gate — the co-scrub is over `registration_envelope`, and `roles` is a
    /// separate column, so the added role does not perturb admission — and
    /// (b) preserves the `canonical` identity_type the genesis seed
    /// re-verify (`verify_canonical_seeded`) asserts. So when server hands us
    /// the re-blessed `SignedKeyRecord` for `canonical_seed.json`, the seed
    /// swap is a drop-in: both gates already accept it, and BOTH effective
    /// roles read true. (The seed JSON change itself waits on that
    /// accord-holder-signed record — this proves persist is ready for it.)
    #[tokio::test]
    async fn canonical_record_with_infra_serve_role_admits_and_reads_both_480() {
        use crate::federation::admission::{
            check_canonical_role_admission_over_roster_legacy,
            has_accord_conferred_role_over_roster,
        };
        use crate::federation::operational::test_support::{
            register_accord_holder, signed_canonical_record_with_roles, Identity,
            PLACEHOLDER_SUBJECT_ED25519_BASE64,
        };
        use crate::federation::types::identity_type;
        let backend = test_backend();
        let holders = [
            Identity::new("h0-480"),
            Identity::new("h1-480"),
            Identity::new("h2-480"),
        ];
        for h in &holders {
            register_accord_holder(&backend, h).await.unwrap();
        }
        let roster: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();

        // canonical,node + infra:serve, genuinely 2-of-3 co-scrubbed.
        let rec = signed_canonical_record_with_roles(
            "ciris-canonical-test-480",
            "canonical,node",
            PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            vec!["infra:serve".to_owned()],
            serde_json::json!({ "key_id": "ciris-canonical-test-480" }),
            &[&holders[0], &holders[1]],
        );

        // (a) the canonical admission gate accepts the added role.
        check_canonical_role_admission_over_roster_legacy(&backend, &rec, &roster)
            .await
            .expect("(480a) canonical admission accepts a record carrying infra:serve");

        // (b) the seed re-verify invariant: canonical role preserved.
        assert!(
            identity_type::set_contains(&rec.identity_type, identity_type::CANONICAL),
            "(480b) verify_canonical_seeded's `canonical` invariant holds"
        );

        // Store + read both effective roles (put_public_key here would fire
        // the PRODUCTION-roster canonical gate, so seed the row directly via
        // the state — the read path is what #480 cares about).
        backend.seed_key_row_unchecked_for_test(rec.clone());
        assert!(
            has_accord_conferred_role_over_roster(
                &backend,
                "ciris-canonical-test-480",
                identity_type::CANONICAL,
                &roster
            )
            .await
            .unwrap(),
            "(480) canonical role reads effective"
        );
        assert!(
            has_accord_conferred_role_over_roster(
                &backend,
                "ciris-canonical-test-480",
                "infra:serve",
                &roster
            )
            .await
            .unwrap(),
            "(480) infra:serve role ALSO reads effective — the trace-serve gate opens"
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
        d.attestation_envelope = serde_json::json!({
            "references_attestation_id": id,
            "scope": scope,
            "pre_rotation_commitment": commitment,
            // #973 — a charter names its job; an unlabelled one is no charter.
            "dimension": crate::federation::trust_root::TRUST_CHARTER_DIMENSION,
        });
        resign_fix(&mut d);
        d
    }

    #[tokio::test]
    async fn sqlite_withdraws_admission_rules_2_3_and_refusal() {
        let backend = test_backend();
        for k in ["prod", "s1", "s2", "proxy", "canon", "rando"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        // Target T: producer `prod`, subjects {s1, s2, canon}.
        let mut t = fix_attestation("t-1", "prod", "prod", "prod");
        t.subject_key_ids = vec!["s1".into(), "s2".into(), "canon".into()];
        crate::federation::tier_ingest::test_support::reseal(&mut t);
        backend
            .put_attestation(SignedAttestation { attestation: t })
            .await
            .unwrap();

        // Rule 2 + §8.1.11.2 — only s1 revokes; admitted under rule 2.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_withdraws("w-s1", "s1", "t-1"),
            })
            .await
            .unwrap();
        let got = backend.get_attestation("w-s1").await.unwrap().unwrap();
        assert_eq!(got.withdraws_admission_rule, Some(2));

        // Rule 3 — proxy holds consent_revocation delegation to `canon`.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "d-1",
                    "proxy",
                    "canon",
                    serde_json::json!(["share", "consent_revocation"]),
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_withdraws("w-proxy", "proxy", "t-1"),
            })
            .await
            .unwrap();
        let got = backend.get_attestation("w-proxy").await.unwrap().unwrap();
        assert_eq!(got.withdraws_admission_rule, Some(3));

        // Refusal — `rando` is neither producer, subject, nor delegate.
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_withdraws("w-bad", "rando", "t-1"),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_withdraws_not_admitted");
        assert!(backend.get_attestation("w-bad").await.unwrap().is_none());
    }

    // ── v8.7.1 (CIRISPersist#233, CEG RC24/RC25/RC26 §11.10/§11.11/
    // §5.6.8.10) — FULL §11.10 moderation enforcement on the report→
    // `scores` path (review / moderation dimensions), memory-backend
    // (3-backend parity with sqlite + postgres). Replaces the v8.7.0
    // on_behalf_of model. Exercises the full matrix: (a) as-self subject,
    // (b1) subject-delegated chain, (b2) named-moderator, (c) no authority,
    // (c2) nothing → REJECT (the bypass-closed guard), (d) scope isolation,
    // (e) depth>5, (f) ⊆-parent attenuation violation, (g) deputization
    // without sub_delegation, (h) withdraws on mid-chain edge, (i)
    // non-steward-bound root.

    /// A `user`-role key (steward-bound by clause (1) of `is_steward_bound`).
    fn fix_user_key(key_id: &str) -> KeyRecord {
        let mut k = fix_key(key_id, "primitive", key_id);
        k.identity_type = crate::federation::types::identity_type::USER.into();
        k
    }

    /// Build a memory-backend `scores` report on `dimension`, signed by
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
            env["community_id"] = serde_json::Value::String(c.to_owned());
        }
        a.attestation_envelope = env;
        resign_fix(&mut a); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        a.subject_key_ids = subject_key_ids.iter().map(|s| (*s).to_owned()).collect();
        crate::federation::tier_ingest::test_support::reseal(&mut a);
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
        // The community's own key must exist in federation_keys.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key(community_id, "primitive", community_id),
            })
            .await
            .unwrap();
        backend
            .put_community(
                crate::federation::tier_ingest::test_support::sign_community(
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
                        consensus_protocol:
                            crate::federation::types::consensus_protocol::FOUNDER_ONLY.into(),
                        policy_blob: None,
                        persist_row_hash: String::new(),
                    },
                ),
            )
            .await
            .expect("seed community");
    }

    #[tokio::test]
    async fn sqlite_moderation_scores_review_full_matrix() {
        let backend = test_backend();
        // `subject` is a user (steward-bound), the content's own subject.
        // `delegate`/`deep` are agent keys; `founder` is the community's
        // steward-bound authority; `rando`/`modkey` are unauthorized.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("subject"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("founder"),
            })
            .await
            .unwrap();
        for k in ["delegate", "deep", "rando", "modkey", "agentroot"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        seed_community_with_founder(&backend, "comm-1", "founder").await;

        // (a) v21.11.0 (CIRISPersist#517, CC 4.5.5) — as-self subject → REJECT.
        // A reconsideration's REVIEW authority is `is_named_moderator` ONLY;
        // the subject naming ITSELF confers no authority (integrity of the
        // signed subject ≠ authority over the action). `subject` is not a
        // moderator of comm-1, so this is refused (was the spoof: admitted).
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-self",
                    "subject",
                    "reconsideration:case42:v1",
                    &["subject"],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
        assert!(backend.get_attestation("r-self").await.unwrap().is_none());

        // (b1) subject-delegated chain (subject → delegate) → REJECT. The
        // subject never held review authority (it is not a moderator), so it
        // cannot delegate it — the delegation row is admissible, but the
        // delegate's reconsideration is not (#517).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "d-rev",
                    "subject",
                    "delegate",
                    serde_json::json!(["message_io", "review"]),
                ),
            })
            .await
            .unwrap();
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-deleg",
                    "delegate",
                    "reconsideration:case42:v1",
                    &["subject"],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
        assert!(backend.get_attestation("r-deleg").await.unwrap().is_none());

        // (b1') founder-delegated chain (founder → fdelegate, review over
        // comm-1) → ADMIT. The LEGITIMATE delegated-moderator path: authority
        // roots at a real named moderator (founder) and flows down the
        // review-scoped delegation — proving #517 cut only the subject-self
        // seed, not genuine moderator delegation.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("fdelegate", "primitive", "fdelegate"),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "d-frev",
                    "founder",
                    "fdelegate",
                    serde_json::json!(["message_io", "review"]),
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-fdeleg",
                    "fdelegate",
                    "reconsideration:case42:v1",
                    &[],
                    Some("comm-1"),
                ),
            })
            .await
            .expect("(b1') founder-delegated review admitted");
        assert!(backend.get_attestation("r-fdeleg").await.unwrap().is_some());

        // (b2) named-moderator: community founder (steward-bound authority)
        // → ADMIT as-self (community-moderation case #95 unblocked).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-mod",
                    "founder",
                    "reconsideration:case42:v1",
                    &[],
                    Some("comm-1"),
                ),
            })
            .await
            .expect("(b2) named-moderator (founder) admitted");
        assert!(backend.get_attestation("r-mod").await.unwrap().is_some());

        // (c) no authority (rando, claims subject target) → REJECT.
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-rando",
                    "rando",
                    "reconsideration:case42:v1",
                    &["subject"],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
        assert!(backend.get_attestation("r-rando").await.unwrap().is_none());

        // (c2) NOTHING — no subjects, no community → REJECT. THE
        // bypass-closed regression guard: absence is never an admit.
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-nothing",
                    "rando",
                    "reconsideration:case42:v1",
                    &[],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
        assert!(
            backend
                .get_attestation("r-nothing")
                .await
                .unwrap()
                .is_none(),
            "(c2) absent principal must REJECT, not admit"
        );

        // (d) scope isolation — a consent_revocation-only delegation from
        // the subject MUST NOT drive a `review`.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "d-wrongscope",
                    "subject",
                    "modkey",
                    serde_json::json!(["consent_revocation"]),
                ),
            })
            .await
            .unwrap();
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-wrongscope",
                    "modkey",
                    "reconsideration:case42:v1",
                    &["subject"],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
        assert!(backend
            .get_attestation("r-wrongscope")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn sqlite_moderation_scores_moderation_dimension_uses_moderate_scope() {
        // A `moderation:*` scores dimension is gated by the `moderate`
        // scope; a `review`-scoped delegation does NOT satisfy it.
        let backend = test_backend();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("subject"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("founder"),
            })
            .await
            .unwrap();
        seed_community_with_founder(&backend, "comm-1", "founder").await;
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("delegate", "primitive", "delegate"),
            })
            .await
            .unwrap();
        // `review`-scoped delegation → cannot drive a `moderation:*` report.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "d-rev2",
                    "founder",
                    "delegate",
                    serde_json::json!(["review"]),
                ),
            })
            .await
            .unwrap();
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "m-wrongscope",
                    "delegate",
                    "moderation:rogue_action:v1",
                    &["subject"],
                    Some("comm-1"),
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");

        // `moderate`-scoped delegation → ADMIT.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "d-mod",
                    "founder",
                    "delegate",
                    serde_json::json!(["moderate"]),
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "m-ok",
                    "delegate",
                    "moderation:rogue_action:v1",
                    &["subject"],
                    Some("comm-1"),
                ),
            })
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
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("k0"),
            })
            .await
            .unwrap();
        let keys: Vec<String> = (0..n).map(|i| format!("k{i}")).collect();
        for k in keys.iter().skip(1) {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        // Every edge `review`-scoped + sub_delegation so only the depth
        // cap (not the deputization gate) is what rejects.
        for i in 0..(n - 1) {
            backend
                .put_attestation(SignedAttestation {
                    attestation: fix_delegates_to_sub(
                        &format!("d{i}"),
                        &keys[i],
                        &keys[i + 1],
                        serde_json::json!(["review"]),
                        true,
                    ),
                })
                .await
                .unwrap();
        }
        // The signer is the too-deep tail key; the root k0 is the subject.
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-toodeep",
                    &keys[n - 1],
                    "reconsideration:case42:v1",
                    &["k0"],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
    }

    #[tokio::test]
    async fn sqlite_moderation_scores_attenuation_and_subdelegation() {
        // (f) ⊆-parent attenuation violation → REJECT; (g) deputization
        // without sub_delegation → REJECT; (h) withdraws on a mid-chain
        // edge → downstream REJECT; (i) non-steward-bound root → REJECT (b).
        let backend = test_backend();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("subject"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("founder"),
            })
            .await
            .unwrap();
        seed_community_with_founder(&backend, "comm-1", "founder").await;
        for k in ["mid", "leaf", "agentroot", "agdel"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }

        // (g) deputization without sub_delegation: subject → mid (review,
        // sub_delegation=false), mid → leaf (review). mid may exercise the
        // duty but MUST NOT deputize leaf → leaf REJECT.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to_sub(
                    "g-1",
                    "founder",
                    "mid",
                    serde_json::json!(["review"]),
                    false,
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to_sub(
                    "g-2",
                    "mid",
                    "leaf",
                    serde_json::json!(["review"]),
                    true,
                ),
            })
            .await
            .unwrap();
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "g-rep",
                    "leaf",
                    "reconsideration:case42:v1",
                    &["subject"],
                    Some("comm-1"),
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_delegated_scope_unauthorized",
            "(g) deputization without sub_delegation must reject downstream"
        );
        // But `mid` itself (the direct delegate) IS admitted.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "g-mid",
                    "mid",
                    "reconsideration:case42:v1",
                    &["subject"],
                    Some("comm-1"),
                ),
            })
            .await
            .expect("(g) direct delegate (mid) is admitted");

        // (i) non-steward-bound root: agentroot (NOT user-role) → agdel
        // (review). agentroot reaches agdel, but is NOT steward-bound, and is
        // not in any community authority set → agdel REJECT under (b).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "i-1",
                    "agentroot",
                    "agdel",
                    serde_json::json!(["review"]),
                ),
            })
            .await
            .unwrap();
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "i-rep",
                    "agdel",
                    "reconsideration:case42:v1",
                    &["agentroot"],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_delegated_scope_unauthorized",
            "(i) non-steward-bound root cannot confer a delegated duty"
        );

        // (h) withdraws on a mid-chain edge: subject → h_mid (review, sub),
        // h_mid → h_leaf (review). subject then withdraws the subject→h_mid
        // edge → h_leaf REJECT (downstream invalidated).
        for k in ["h_mid", "h_leaf"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to_sub(
                    "h-1",
                    "founder",
                    "h_mid",
                    serde_json::json!(["review"]),
                    true,
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to_sub(
                    "h-2",
                    "h_mid",
                    "h_leaf",
                    serde_json::json!(["review"]),
                    true,
                ),
            })
            .await
            .unwrap();
        // h_leaf admitted BEFORE the withdraws.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "h-pre",
                    "h_leaf",
                    "reconsideration:case42:v1",
                    &["subject"],
                    Some("comm-1"),
                ),
            })
            .await
            .expect("(h) chain valid before withdraws");
        // subject withdraws the subject→h_mid edge (issuer-against-recipient).
        backend
            .put_attestation(SignedAttestation {
                attestation: {
                    let mut w = fix_attestation("h-w", "founder", "h_mid", "founder");
                    w.attestation_type =
                        crate::federation::types::attestation_type::WITHDRAWS.into();
                    w.attestation_envelope =
                        serde_json::json!({"references_attestation_id": "h-1"});
                    resign_fix(&mut w); // envelope changed → re-sign (CC 5.3.2.4.3.1)
                    w
                },
            })
            .await
            .expect("founder withdraws own delegation edge");
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "h-post",
                    "h_leaf",
                    "reconsideration:case42:v1",
                    &["subject"],
                    Some("comm-1"),
                ),
            })
            .await
            .unwrap_err();
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
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("subject"),
            })
            .await
            .unwrap();
        for k in ["mid", "leaf"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        // subject → mid grants {review} (sub_delegation).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to_sub(
                    "att-1",
                    "subject",
                    "mid",
                    serde_json::json!(["review"]),
                    true,
                ),
            })
            .await
            .unwrap();
        // mid → leaf grants {review, moderate} — EXPANDS beyond parent's
        // {review}; the review-scoped edge is present but the scope-set is
        // not ⊆ parent → attenuation rejects the traversal to leaf.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to_sub(
                    "att-2",
                    "mid",
                    "leaf",
                    serde_json::json!(["review", "moderate"]),
                    true,
                ),
            })
            .await
            .unwrap();
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "att-rep",
                    "leaf",
                    "reconsideration:case42:v1",
                    &["subject"],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_delegated_scope_unauthorized",
            "(f) child scope-set must be ⊆ parent scope-set"
        );
    }

    // ── v9.0.0 (CC 3.2 / CC 3.4.7.1) — steward-binding precondition for
    // non-infrastructure community membership (memory backend; 3-backend
    // parity with sqlite + postgres). A node/agent roster member of a
    // non-infra community MUST be steward-bound; infra communities + pure
    // user/canonical participation are not over-rejected.

    /// [`put_community_with_authority`] with the whole `policy_blob` (v54.0.0,
    /// #1034 — an affiliation declares `"cohort_scope": "affiliations"` there).
    async fn put_community_with_policy(
        backend: &SqliteBackend,
        community_id: &str,
        members: Vec<crate::federation::types::CommunityMember>,
        policy_blob: Option<serde_json::Value>,
        comm_authorized: bool,
    ) -> Result<(), crate::federation::Error> {
        let mut comm_key = fix_key(community_id, "primitive", community_id);
        if comm_authorized {
            comm_key.identity_type =
                crate::federation::types::identity_type::SUBSTRATE_PERSIST.into();
        }
        backend
            .put_public_key(SignedKeyRecord { record: comm_key })
            .await
            .unwrap();
        crate::federation::tier_ingest::test_support::register_fixture_infrastructure_founder(
            backend,
        )
        .await;
        backend
            .put_community(
                crate::federation::tier_ingest::test_support::sign_community(
                    community_id,
                    crate::federation::types::Community {
                        prev_head_digest: String::new(),
                        charter_digest: String::new(),
                        community_key_id: community_id.into(),
                        community_name: "ob-test".into(),
                        members: crate::federation::tier_ingest::test_support::fixture_members(
                            policy_blob.as_ref(),
                            members,
                        ),
                        founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                        consensus_protocol:
                            crate::federation::tier_ingest::test_support::fixture_protocol(
                                policy_blob.as_ref(),
                                crate::federation::types::consensus_protocol::FOUNDER_ONLY,
                            ),
                        policy_blob,
                        persist_row_hash: String::new(),
                    },
                ),
            )
            .await
    }

    fn member(key_id: &str) -> crate::federation::types::CommunityMember {
        crate::federation::types::CommunityMember {
            key_id: key_id.into(),
            joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            role: Some("member".into()),
        }
    }

    /// Register a `user`-role key, a node-only key, and an agent key.
    async fn seed_ob_keys(backend: &SqliteBackend) {
        let mut owner = fix_key("ob-owner", "owner", "ob-owner");
        owner.identity_type = crate::federation::types::identity_type::USER.into();
        backend
            .put_public_key(SignedKeyRecord { record: owner })
            .await
            .unwrap();
        let mut node = fix_key("ob-node", "node", "ob-node");
        node.identity_type = crate::federation::types::identity_type::NODE.into();
        backend
            .put_public_key(SignedKeyRecord { record: node })
            .await
            .unwrap();
        let mut agent = fix_key("ob-agent", "agent", "ob-agent");
        agent.identity_type = crate::federation::types::identity_type::AGENT.into();
        backend
            .put_public_key(SignedKeyRecord { record: agent })
            .await
            .unwrap();
    }

    /// CC 4.4.3.2.8 / #308 — the `affiliations` cohort runs the FULL membership
    /// lifecycle (add → active-members → revoke) through the SAME community
    /// machinery as `community`, including the epoch bump (forward secrecy) on
    /// removal. Asserted via the uniform [`FederationDirectory`] cohort surface.
    #[tokio::test]
    async fn affiliations_cohort_membership_lifecycle_mirrors_community() {
        use crate::federation::cohort::{Cohort, RosterMember};
        use crate::federation::FederationDirectory;
        let backend = test_backend();
        seed_ob_keys(&backend).await; // ob-owner (user), ob-node, ob-agent
                                      // A second user-role key to add to the roster.
        let mut joiner = fix_key("ob-joiner", "owner", "ob-joiner");
        joiner.identity_type = crate::federation::types::identity_type::USER.into();
        backend
            .put_public_key(SignedKeyRecord { record: joiner })
            .await
            .unwrap();
        // The affiliations group is a community row (shared storage), founded
        // by the user-role member ob-owner.
        let group = "aff-grp";
        // v49.0.0 (#908): ob-owner founds the group, so its signature is
        // the founder_only protocol.
        let mut founder = member("ob-owner");
        founder.role = Some("founder".into());
        // v54.0.0 (#1034) — the record DECLARES itself an affiliation; a
        // plain community addressed as one is refused.
        put_community_with_policy(
            &backend,
            group,
            vec![founder],
            Some(serde_json::json!({ "cohort_scope": "affiliations" })),
            false,
        )
        .await
        .expect("affiliations group (community row) created");

        // ── add via the affiliations cohort ────────────────────────────────
        // v31.0.0 (CIRISPersist#654) — signed over the GROWN community envelope.
        let joiner_row = RosterMember {
            key_id: "ob-joiner".into(),
            joined_at: chrono::Utc::now(),
            role: Some("member".into()),
        };
        let admit = crate::federation::cohort::test_support::admit_roster_member_via(
            &backend,
            "ob-owner",
            Cohort::Affiliations,
            group,
            &joiner_row,
        )
        .await;
        let added = backend
            .add_member_consented(Cohort::Affiliations, group, joiner_row, &admit)
            .await
            .expect("affiliations add_member");
        assert!(added, "genuine add returns true");

        // active_members(affiliations) reads the shared community roster.
        let active: Vec<String> = backend
            .active_members(Cohort::Affiliations, group)
            .await
            .expect("affiliations active_members")
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        assert!(active.contains(&"ob-owner".to_string()));
        assert!(
            active.contains(&"ob-joiner".to_string()),
            "added member visible via the affiliations cohort"
        );
        // v54.0.0 (Codex round 2 on PR #1050) — the roster is shared storage,
        // but the record declares `affiliations`: read under `community` it is
        // refused, never answered with the same roster (I606).
        assert!(
            matches!(
                backend.active_members(Cohort::Community, group).await,
                Err(crate::federation::Error::AffiliationCohortMismatch { .. })
            ),
            "an affiliation read under the community cohort is a cohort mismatch"
        );

        // ── revoke via the affiliations cohort → epoch bump (forward secrecy) ─
        assert_eq!(backend.community_dek_epoch(group), 0, "epoch starts 0");
        backend
            .revoke_member(
                Cohort::Affiliations,
                group,
                "ob-joiner",
                crate::federation::tier_ingest::test_support::sign_revoke_spec(
                    Cohort::Affiliations,
                    "ob-joiner",
                    // v49.0.0 (#908): the member leaves on their own signature.
                    group,
                    "ob-joiner",
                    chrono::Utc::now(),
                    Some("left".into()),
                    vec![],
                ),
            )
            .await
            .expect("affiliations revoke_member");
        assert_eq!(
            backend.community_dek_epoch(group),
            1,
            "affiliations removal bumps the CommunityDek epoch (CC 4.4.3.2.2 forward secrecy)"
        );
        let active_after: Vec<String> = backend
            .active_members(Cohort::Affiliations, group)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        assert!(
            !active_after.contains(&"ob-joiner".to_string()),
            "revoked member dropped from the active affiliations roster"
        );
    }

    /// CC 4.4.3.2.8 / #308 — `affiliations` resolves to the `CommunityDek`
    /// crypto tier (the same tier as `community`), and the negative-default
    /// holds: `self`/`family` → InvisibleEncrypted, an unknown scope →
    /// Plaintext, infrastructure-subkind → Plaintext.
    #[test]
    fn affiliations_resolves_to_community_dek_tier() {
        use crate::federation::types::cohort_scope::{crypto_tier, CryptoTier, AFFILIATIONS};
        assert_eq!(
            crypto_tier(AFFILIATIONS, None),
            CryptoTier::CommunityDek,
            "affiliations → CommunityDek (CC 4.4.3.2.8)"
        );
        // Same tier as community (shared machinery).
        assert_eq!(crypto_tier("community", None), CryptoTier::CommunityDek);
        // Infrastructure carve-out → Plaintext even for affiliations.
        assert_eq!(
            crypto_tier(AFFILIATIONS, Some("infrastructure")),
            CryptoTier::Plaintext
        );
        // self/family → InvisibleEncrypted; unknown → Plaintext (negative default).
        assert_eq!(crypto_tier("self", None), CryptoTier::InvisibleEncrypted);
        assert_eq!(crypto_tier("family", None), CryptoTier::InvisibleEncrypted);
        assert_eq!(crypto_tier("federation", None), CryptoTier::Plaintext);
        assert_eq!(crypto_tier("nonsense-scope", None), CryptoTier::Plaintext);
    }

    // ── v3.1.0 (CIRISPersist#117) — peer-mutation surface ──────────

    // ── BlackholeRules tests (v3.2.0, CIRISPersist#120) ────────────

    // ─── v6.7.0 Lane G (CEG 1.0-RC5) — consent clauses ─────────────

    use crate::federation::types::consent_record;

    // ── Clause 1 (#161 Ask 5, CEG §7.7) — removal-path emission ────

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
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, k, "registry-steward"),
                })
                .await
                .unwrap();
        }
        backend
    }

    #[tokio::test]
    async fn consent_record_granted_federation_admits() {
        let backend = consent_backend().await;
        let row = consent_record_row(
            "cr-1",
            "subject-key",
            consent_record::stance::GRANTED,
            crate::federation::types::attestation_tier::FEDERATION,
            true,
        );
        backend
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("granted/federation consent_record admits");
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
        let err = backend
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::federation::Error::InvalidArgument(ref m) if m.contains("subject_key_id")),
            "missing required field rejected, got {err:?}"
        );
    }

    #[tokio::test]
    async fn consent_record_producer_submitted_expired_rejected() {
        let backend = consent_backend().await;
        let row = consent_record_row(
            "cr-3",
            "subject-key",
            consent_record::stance::EXPIRED,
            crate::federation::types::attestation_tier::FEDERATION,
            true,
        );
        let err = backend
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::federation::Error::InvalidArgument(ref m) if m.contains("substrate-emitted only")),
            "producer-submitted expired rejected, got {err:?}"
        );
    }

    /// v12.6.0 (CIRISPersist#171, §10.1.3 transit-not-rest) — a `revoked`
    /// consent_record at local tier is ACCEPTED as a **transit** write when
    /// its bound-hybrid signature verifies (the operator decision), but a
    /// crypto-INVALID one is rejected at admission (never rests unsigned).
    /// Pre-v12.6.0 this was a hard rejection of both.
    #[tokio::test]
    async fn consent_record_revoked_local_tier_transits_iff_signed() {
        let backend = consent_backend().await;
        // (1) Validly-signed revoked consent_record @ local → transit-accepted.
        let row = consent_record_row(
            "cr-4",
            "subject-key",
            consent_record::stance::REVOKED,
            crate::federation::types::attestation_tier::LOCAL,
            true,
        );
        backend
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("crypto-valid revoked consent_record transits the local tier (§10.1.3)");

        // (2) A crypto-INVALID one (signature corrupted) is rejected at
        // admission — accept ONLY on a valid bound-hybrid signature.
        let mut forged = consent_record_row(
            "cr-4b",
            "subject-key",
            consent_record::stance::REVOKED,
            crate::federation::types::attestation_tier::LOCAL,
            true,
        );
        forged.scrub_signature_classical = "AAAA".into(); // not a valid sig
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: forged,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::federation::Error::FederationTierUnverified { .. }
            ),
            "unsigned/forged revoked consent_record rejected at admission, got {err:?}"
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
            crate::federation::envelope::paths::ASSERTED_AT: row.asserted_at.to_rfc3339(),
        });
        row.subject_key_ids = vec!["subject-key".into()];
        row.tier = crate::federation::types::attestation_tier::LOCAL.into();
        row.cohort_scope = crate::federation::types::cohort_scope::SELF.to_string();
        resign_fix(&mut row); // envelope changed → re-sign
        let mut forged = row.clone();
        backend
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("crypto-valid bare subject-side revocation transits at local tier");

        // Forged signature → rejected (no put_attestation bypass of the gate).
        forged.attestation_id = "bare-rev-forged".into();
        crate::federation::tier_ingest::test_support::reseal(&mut forged);
        forged.scrub_signature_classical = "AAAA".into();
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: forged,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::federation::Error::FederationTierUnverified { .. }
            ),
            "forged bare revocation rejected at put_attestation local tier, got {err:?}"
        );
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
        backend
            .put_attestation(SignedAttestation { attestation: row })
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
        let err = backend
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::federation::Error::InvalidArgument(ref m) if m.contains("closed set")),
            "out-of-closed-set stance rejected, got {err:?}"
        );
    }

    // ── Clause 3 (#146 Ask 6, CEG §5.6.8.14) — canonical_binding ───

    // ── v9.1.0 (CC 1.13.3 / FSD §2.4, CIRISPersist#243) scope-blob store ──

    // ── #249 Cut B — CEG-native graph DX enumerators + add_community_member.

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
        use crate::federation::types::{consensus_protocol, identity_type};

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
            let mut ck = fix_key(cid, "primitive", cid);
            if infra {
                // SecReview F2: the infra carve-out is honored only when the
                // community's own key is the substrate_persist authority.
                ck.identity_type = identity_type::SUBSTRATE_PERSIST.into();
            }
            backend
                .put_public_key(SignedKeyRecord { record: ck })
                .await
                .unwrap();
            let mut fk = fix_key(founder, "primitive", founder);
            fk.identity_type = founder_it.into();
            backend
                .put_public_key(SignedKeyRecord { record: fk })
                .await
                .unwrap();
            let policy_blob =
                infra.then(|| serde_json::json!({ "cohort_subkind": "infrastructure" }));
            let community = crate::federation::types::Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: cid.into(),
                community_name: "dt".into(),
                members: vec![crate::federation::types::CommunityMember {
                    key_id: founder.into(),
                    joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                    role: Some(MEMBER_ROLE_FOUNDER.into()),
                }],
                founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                consensus_protocol: crate::federation::tier_ingest::test_support::fixture_protocol(
                    policy_blob.as_ref(),
                    consensus_protocol::FOUNDER_ONLY,
                ),
                policy_blob,
                persist_row_hash: String::new(),
            };
            backend
                .put_community(
                    crate::federation::tier_ingest::test_support::sign_community(
                        cid,
                        community.clone(),
                    ),
                )
                .await
                .expect("record stored (put_community is not the moderator gate)");
            community
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

        // (3) infrastructure community with a non-steward-bound founder →
        //     EXEMPT (trust + serve needs no moderator) → ADMIT.
        let c_infra = seed(&b, "dt-infra", "dt-iprim", identity_type::PRIMITIVE, true).await;
        check_no_moderator_federate_admission(&b, &c_infra)
            .await
            .expect("authorized infrastructure community is exempt from the moderator gate");

        // ── federation-apply chokepoint (points i + ii unified) ─────────────
        // A federation-tier row keyed on the moderator-less community → REJECT.
        let mut row = fix_attestation("dt-apply", "dt-prim", "dt-prim", "dt-prim");
        row.attestation_envelope = serde_json::json!({
            "id": "dt-apply", "dimension": "identity_binding:v1", "community_id": "dt-no"
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
            "id": "dt-apply2", "dimension": "identity_binding:v1", "community_id": "dt-ok"
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
        use crate::federation::types::{consensus_protocol, identity_type};

        let b = test_backend();

        // Seed a MODERATOR-LESS community (primitive founder — passes the
        // steward-binding storage gate, but is NOT steward-bound ⇒ no
        // zero-hop moderator) and a MODERATORED one (user founder).
        async fn seed(backend: &SqliteBackend, cid: &str, founder: &str, founder_it: &str) {
            let ck = fix_key(cid, "primitive", cid);
            backend
                .put_public_key(SignedKeyRecord { record: ck })
                .await
                .unwrap();
            let mut fk = fix_key(founder, "primitive", founder);
            fk.identity_type = founder_it.into();
            backend
                .put_public_key(SignedKeyRecord { record: fk })
                .await
                .unwrap();
            backend
                .put_community(
                    crate::federation::tier_ingest::test_support::sign_community(
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
                            consensus_protocol: consensus_protocol::FOUNDER_ONLY.into(),
                            policy_blob: None,
                            persist_row_hash: String::new(),
                        },
                    ),
                )
                .await
                .expect("storage-only put_community is NOT the moderator gate");
        }
        seed(&b, "bk-no", "bk-prim", identity_type::PRIMITIVE).await;
        seed(&b, "bk-ok", "bk-user", identity_type::USER).await;

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
        crate::federation::tier_ingest::test_support::reseal(&mut row);
        refused(
            check_no_moderator_federate_apply(&b, &row)
                .await
                .unwrap_err(),
            "attested_key_id = C",
        );
        // Same shape onto the MODERATORED community → ADMIT.
        let mut ok_row = fix_attestation("bk-2", "bk-user", "bk-ok", "bk-user");
        ok_row.attestation_envelope = bare_env.clone();
        crate::federation::tier_ingest::test_support::reseal(&mut ok_row);
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
        crate::federation::tier_ingest::test_support::reseal(&mut by_c);
        refused(
            check_no_moderator_federate_apply(&b, &by_c)
                .await
                .unwrap_err(),
            "attesting_key_id = C",
        );

        // (3) subject_key_ids shape → REJECT; non-community subjects fail-open.
        let mut subj = fix_attestation("bk-4", "bk-prim", "bk-prim", "bk-prim");
        subj.attestation_envelope = bare_env.clone();
        subj.subject_key_ids = vec!["not-a-community".into(), "bk-no".into()];
        crate::federation::tier_ingest::test_support::reseal(&mut subj);
        refused(
            check_no_moderator_federate_apply(&b, &subj)
                .await
                .unwrap_err(),
            "subject_key_ids ∋ C",
        );
        let mut subj_ok = subj.clone();
        subj_ok.subject_key_ids = vec!["not-a-community".into(), "bk-ok".into()];
        crate::federation::tier_ingest::test_support::reseal(&mut subj_ok);
        check_no_moderator_federate_apply(&b, &subj_ok)
            .await
            .expect("subject-keyed row onto a moderatored community is admitted");

        // (4) Sibling envelope field names (`community_key_id` / `cohort_key_id`)
        //     → REJECT on the moderator-less community.
        for field in ["community_key_id", "cohort_key_id"] {
            let mut env_row = fix_attestation("bk-5", "bk-prim", "bk-prim", "bk-prim");
            env_row.attestation_envelope = serde_json::json!({
                "id": "bk-5", "dimension": "identity_binding:v1", field: "bk-no"
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
        seed(&b, "bk-no", "bk-prim", identity_type::PRIMITIVE).await;
        b.put_community_membership_revocation(
            crate::federation::tier_ingest::test_support::sign_community_membership_revocation(
                // v49.0.0 (#908): the member leaves on their own signature —
                // nobody holds standing in a moderator-less founder_only room.
                "bk-prim",
                crate::federation::types::CommunityMembershipRevocation {
                    community_key_id: "bk-no".into(),
                    removed_identity_key_id: "bk-prim".into(),
                    removed_at: "2026-05-02T00:00:00Z".parse().unwrap(),
                    effective_at: "2026-05-02T00:00:00Z".parse().unwrap(),
                    reason: Some("storage-only membership op stays ungated".into()),
                    witness_set: Vec::new(),
                    persist_row_hash: String::new(),
                },
            ),
        )
        .await
        .expect("membership revocation on a moderator-less community is storage, not federation");

        // (6) The drivable verdict mirrors the gate decision exactly.
        let v = no_moderator_federate_verdict(&b, "bk-no").await.unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "admitted": false, "community_known": true,
                "reason": "federation_community_no_moderator"
            })
        );
        let v = no_moderator_federate_verdict(&b, "bk-ok").await.unwrap();
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

    // ── CIRISConstitution#23 (CC 1.13.3.3 / CC 3.2) — single-owner gate ──

    /// Build an OWNER-BINDING `delegates_to(owner → node)` carrying the CC
    /// 1.13.3.3 / CC 3.2 ownership dimension (what the single-owner gate +
    /// `owner_of` key on) with infra-only scope, re-signed for the
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
        let mut u = fix_key(key_id, key_id, key_id);
        u.identity_type = crate::federation::types::identity_type::USER.into();
        backend
            .put_public_key(SignedKeyRecord { record: u })
            .await
            .unwrap();
    }

    /// A node cannot accrue a SECOND, distinct owner: the first owner-binding
    /// admits; a second from a DIFFERENT user is rejected `NodeAlreadyOwned`
    /// and leaves no trace (verify-before-mutation). This is what keeps the
    /// `self` cohort boundary single-valued.
    #[tokio::test]
    async fn single_owner_gate_rejects_second_distinct_owner() {
        use crate::federation::admission::owner_of;
        let backend = test_backend();
        seed_ob_keys(&backend).await; // ob-owner (user), ob-node (node)
        seed_second_owner(&backend, "ob-owner2").await;

        // First owner-binding admits; owner_of resolves ob-owner.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding("ob-b1", "ob-owner", "ob-node"),
            })
            .await
            .unwrap();
        assert_eq!(
            owner_of(&backend, "ob-node").await.unwrap(),
            Some("ob-owner".to_string())
        );

        // A second, DIFFERENT owner is rejected.
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding("ob-b2", "ob-owner2", "ob-node"),
            })
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::NodeAlreadyOwned {
                ref node_key_id,
                ref incumbent_owner,
                ref attempted_owner,
            } => {
                assert_eq!(node_key_id, "ob-node");
                assert_eq!(incumbent_owner, "ob-owner");
                assert_eq!(attempted_owner, "ob-owner2");
            }
            other => panic!("expected NodeAlreadyOwned, got {other:?}"),
        }
        assert_eq!(err.kind(), "federation_node_already_owned");
        // The rejected binding left no trace — owner unchanged.
        assert_eq!(
            owner_of(&backend, "ob-node").await.unwrap(),
            Some("ob-owner".to_string())
        );
    }

    /// v13.3.0 (CIRISPersist#378) — the owner-binding built with the **CC
    /// 2.4.1.2 canonical marker only** (`delegation_purpose: "owner_binding"`,
    /// **no `dimension`**) — the shape a raw `emit_attestation_self` `delegates_to`
    /// carries, and exactly what CIRISConformance `test_551` probes. Before the
    /// fix, the gate keyed on the internal dimension alone and this path was
    /// UNGATED (a second distinct owner was admitted — CC 3.2 violated).
    fn fix_owner_binding_cc(id: &str, owner: &str, node: &str) -> Attestation {
        use crate::federation::types::{attestation_type, delegation_scope as ds, owner_binding};
        let mut att = fix_attestation(id, owner, node, owner);
        att.attestation_type = attestation_type::DELEGATES_TO.into();
        crate::federation::tier_ingest::test_support::reseal(&mut att);
        // CC 2.4.1.2 marker ONLY (no `dimension`). Carries the infra scopes so
        // it clears the node-agency gate and actually reaches the single-owner
        // gate under test (the marker recognition is the thing being proven).
        att.attestation_envelope = serde_json::json!({
            "id": id,
            "kind": "delegates_to",
            "delegation_purpose": owner_binding::CC_DELEGATION_PURPOSE,
            "scope": [ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
        });
        resign_fix(&mut att);
        att
    }

    /// v13.3.0 (CIRISPersist#378) — the single-owner gate + `owner_of` now fire
    /// on the **CC-marker raw-emit path** (`delegation_purpose: "owner_binding"`,
    /// no dimension), not only persist's internal-dimension `steward_bind` path.
    /// A second distinct owner via the raw path is rejected; `owner_of` resolves
    /// the first. This is the exact bypass CIRISConformance `test_551` caught.
    #[tokio::test]
    async fn single_owner_gate_rejects_second_distinct_owner_via_cc_marker() {
        use crate::federation::admission::owner_of;
        let backend = test_backend();
        seed_ob_keys(&backend).await;
        seed_second_owner(&backend, "ob-owner2").await;

        // First owner-binding (CC marker, no dimension) admits; owner_of resolves.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding_cc("ob-cc1", "ob-owner", "ob-node"),
            })
            .await
            .unwrap();
        assert_eq!(
            owner_of(&backend, "ob-node").await.unwrap(),
            Some("ob-owner".to_string()),
            "owner_of must resolve the CC-marker owner-binding"
        );

        // A second, DIFFERENT owner via the same CC-marker path is REJECTED.
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding_cc("ob-cc2", "ob-owner2", "ob-node"),
            })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_node_already_owned",
            "second distinct owner via the CC-marker raw-emit path must be rejected, got {err:?}"
        );
        assert_eq!(
            owner_of(&backend, "ob-node").await.unwrap(),
            Some("ob-owner".to_string()),
            "the rejected second binding left no trace"
        );
    }

    /// A refresh by the SAME owner (new attestation id, same granter) is
    /// idempotently admitted — re-binding your own node is not a second owner.
    #[tokio::test]
    async fn single_owner_gate_admits_same_owner_refresh() {
        use crate::federation::admission::owner_of;
        let backend = test_backend();
        seed_ob_keys(&backend).await;
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding("ob-b1", "ob-owner", "ob-node"),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding("ob-b2", "ob-owner", "ob-node"),
            })
            .await
            .unwrap();
        assert_eq!(
            owner_of(&backend, "ob-node").await.unwrap(),
            Some("ob-owner".to_string())
        );
    }

    /// Ownership is transferable, not permanent: after the incumbent binding
    /// lapses (expiry → non-live), a DIFFERENT owner may bind. The gate honors
    /// the same liveness predicate as `steward_bindings_of`.
    #[tokio::test]
    async fn single_owner_gate_admits_new_owner_after_incumbent_expires() {
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
        backend
            .put_attestation(SignedAttestation {
                attestation: expired,
            })
            .await
            .unwrap();
        // Expired → non-live → node reads as unowned.
        assert_eq!(owner_of(&backend, "ob-node").await.unwrap(), None);

        // A different owner may now bind.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding("ob-b2", "ob-owner2", "ob-node"),
            })
            .await
            .unwrap();
        assert_eq!(
            owner_of(&backend, "ob-node").await.unwrap(),
            Some("ob-owner2".to_string())
        );
    }

    /// The gate + `owner_of` key on the OWNERSHIP dimension, NOT any
    /// `delegates_to`. A plain infra delegation (act-on-behalf shape, no
    /// ownership dimension) is not an owner-binding: it neither trips the gate
    /// nor counts toward `owner_of` — even though `steward_bindings_of` (the
    /// broader relation) does count it. This is the ownership-vs-delegation
    /// distinction the single-owner invariant rests on.
    #[tokio::test]
    async fn owner_of_ignores_non_ownership_delegations() {
        use crate::federation::admission::{owner_of, steward_bindings_of};
        use crate::federation::types::delegation_scope as ds;
        let backend = test_backend();
        seed_ob_keys(&backend).await;
        seed_second_owner(&backend, "ob-owner2").await;

        // A non-ownership infra delegation (no ownership dimension).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_node_delegates_to(
                    "ob-plain",
                    "ob-owner",
                    "ob-node",
                    "ob-owner",
                    &[ds::INFRA_SERVE],
                ),
            })
            .await
            .unwrap();
        // Not an owner-binding → owner_of sees no owner…
        assert_eq!(owner_of(&backend, "ob-node").await.unwrap(), None);
        // …but steward_bindings_of (broader) DOES count the granter.
        assert_eq!(
            steward_bindings_of(&backend, "ob-node").await.unwrap(),
            vec!["ob-owner".to_string()]
        );
        // A real owner-binding from a DIFFERENT user still admits — the plain
        // delegation never claimed ownership, so it does not block.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding("ob-b1", "ob-owner2", "ob-node"),
            })
            .await
            .unwrap();
        assert_eq!(
            owner_of(&backend, "ob-node").await.unwrap(),
            Some("ob-owner2".to_string())
        );
    }

    /// `owner_of` on an unowned node is `None` (not an error, not a guess).
    #[tokio::test]
    async fn owner_of_unowned_node_is_none() {
        let backend = test_backend();
        seed_ob_keys(&backend).await;
        assert_eq!(
            crate::federation::admission::owner_of(&backend, "ob-node")
                .await
                .unwrap(),
            None
        );
    }

    /// (CIRISPersist#593) — the read cost of the new incoming-retraction
    /// clause, MEASURED against this backend's own directory-read counters, and
    /// the proof that the predicate walk still stops at the first hit.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    async fn moderation_walk_read_cost_sqlite_593() {
        let backend = test_backend();
        crate::federation::admission::moderation_walk_liveness_test_support::exercise_moderation_walk_read_cost(
            &backend, "mem",
        )
        .await;
    }

    /// v13.0.1 (#375) — the DEFAULT `FederationDirectory::apply_replicated_key_record`
    /// trait body (memory/mock backends, no scrub-upgrade plane): a new
    /// key_id is a first-seen Inserted; a differing record for an existing
    /// key_id is Refused (fail-closed, first-seen wins) and leaves the row
    /// untouched — no panic, no error propagated up the anti-entropy loop.
    /// v44.7.0 (#864) — with a backend feature on, the memory apply runs the
    /// key plan (insert behind the PoP gate, so the records are SIGNED now)
    /// and names the refusal; without one it is still the plan-less default.
    #[tokio::test]
    async fn apply_replicated_key_record_default_first_seen_wins_sqlite() {
        use crate::federation::register::ReplicatedKeyOutcome;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::FederationDirectory;
        let backend = test_backend();
        let dir: &dyn FederationDirectory = &backend;

        // First-seen insert.
        assert_eq!(
            dir.apply_replicated_key_record(SignedKeyRecord {
                record: ts::replicated_key_record("node-x", "primitive", "node-x", "node-x", "n1"),
            })
            .await
            .unwrap(),
            ReplicatedKeyOutcome::Inserted
        );

        // A differing record for the same key_id — Refused, original kept.
        // v22.0.0 (CIRISPersist#543): a REAL, structurally-valid 32-byte
        // Ed25519 key that merely differs. The old `"AAAA-different-pubkey"`
        // placeholder is not even base64, so with #275's
        // `validate_registration_pubkey` now running on memory it would fail
        // admission instead of reaching the first-seen-wins decision this
        // test is about — and it would never have reached it on sqlite or
        // postgres either.
        let mut differing =
            ts::replicated_key_record("node-x", "primitive", "node-x", "node-x", "n2");
        differing.pubkey_ed25519_base64 = ts::hybrid_pubkeys("node-x-other").0;
        #[cfg(any(feature = "postgres", feature = "sqlite"))]
        let expected = crate::federation::register::KeyRefusalReason::PubkeySwap;
        #[cfg(not(any(feature = "postgres", feature = "sqlite")))]
        let expected = crate::federation::register::KeyRefusalReason::StoreConflict;
        assert_eq!(
            dir.apply_replicated_key_record(SignedKeyRecord { record: differing })
                .await
                .unwrap(),
            // v24.2.0 (CIRISPersist#565) — a body that runs no plan may only
            // say `StoreConflict`. v44.7.0 (#864) — this backend now runs the
            // key plan first (it has to, to see a rebind), so the differing
            // row is refused by NAME. First-seen still wins: the row is kept.
            ReplicatedKeyOutcome::Refused { reason: expected }
        );
        let row = dir.lookup_public_key("node-x").await.unwrap().unwrap();
        assert_eq!(row.scrub_key_id, "node-x", "original self-signed row kept");
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
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        // A scope-bearing (`moderate`) delegation edge.
        let delegate = |id: &str, granter: &str, grantee: &str| {
            let mut d = fix_attestation(id, granter, grantee, granter);
            d.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
            crate::federation::tier_ingest::test_support::reseal(&mut d);
            d.attestation_envelope = serde_json::json!({
                "references_attestation_id": id,
                "scope": [DELEGATION_SCOPE_MODERATE],
                "sub_delegation": true,
            });
            resign_fix(&mut d);
            d
        };
        // A `withdraws` keyed on the recipient (the scoped walk's edge-
        // retraction model — `attested_key_id == recipient`).
        let withdraw_edge = |id: &str, granter: &str, recipient: &str| {
            let mut w = fix_attestation(id, granter, recipient, granter);
            w.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.into();
            resign_fix(&mut w);
            w
        };
        for a in [
            delegate("ar-d", "ar-root", "ar-tgt"), // Reachable / MissingScope pair
            delegate("br-d", "br-root", "br-tgt"), // RetractedAtRoot pair
            withdraw_edge("br-w", "br-root", "br-tgt"), // … retracted
            delegate("cr-d", "cr-root", "cr-mid"), // SignerUnreached: edge, but not to tgt
        ] {
            backend
                .put_attestation(SignedAttestation { attestation: a })
                .await
                .unwrap();
        }
        let depth = MAX_MODERATION_DELEGATION_DEPTH;
        let verdict = |issuer: &'static str, tgt: &'static str, scope: &'static str| {
            let b = &backend;
            async move {
                reachable_under_scope_with_reasons(b, issuer, tgt, scope, depth)
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
            "ar-root",
            "ar-tgt",
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
            let mut rec = fix_key(k, "ref", k);
            rec.identity_type = it.to_owned();
            // v22.0.0 (CIRISPersist#543) — the memory backend now runs the
            // same `accord_holder` hardware gate sqlite/postgres do, so an
            // `accord_holder` fixture must carry real evidence. No-op for
            // every other identity_type.
            crate::federation::hardware_attestation::test_support::attach_hardware_evidence(
                &mut rec,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
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
        check_reserved_prefix_admission(
            &backend,
            &row("accord:invoke:notify:x", "rp-accord", "rp-accord"),
        )
        .await
        .expect("accord_holder may emit accord:*");

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
            "dimension": "test:oversize:v1",
        });

        // Federation put: refused before signature/directory work.
        let mut row = fix_attestation("cap-fed", "cap-k", "cap-k", "cap-k");
        row.attestation_envelope = oversize.clone();
        crate::federation::tier_ingest::test_support::reseal(&mut row);
        let err = backend
            .put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await
            .expect_err("oversize federation put must refuse");
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

    /// v47.1.0 (CIRISPersist#861) — both removal doors are idempotent on
    /// their PK on memory too: a repeat is `Ok`, the first stands, and the
    /// community repeat does not rotate the DEK epoch a second time. (The
    /// sqlite/postgres legs are `exercise_family_revocation_repeat_861` and
    /// step 4b of the cohort lifecycle.)
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    async fn revocation_repeat_is_a_noop_sqlite_861() {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::FederationDirectory;
        let b = test_backend();
        let (fam, cid, alice, bob) = ("fam-861", "comm-861", "alice-861", "bob-861");
        for k in [fam, cid, alice, bob] {
            ts::register_identity_key(&b, k, crate::federation::types::identity_type::USER).await;
        }
        let now = chrono::Utc::now();
        b.put_family(ts::sign_family(
            fam,
            crate::federation::types::Family {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                family_key_id: fam.into(),
                family_name: "861".into(),
                members: [alice, bob]
                    .iter()
                    .map(|k| crate::federation::types::FamilyMember {
                        key_id: (*k).into(),
                        joined_at: now,
                        role: None,
                    })
                    .collect(),
                founded_at: now,
                consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY.into(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("family");
        ts::seed_two_member_community(&b, cid, alice, bob).await;

        let first = now - chrono::Duration::seconds(5);
        // v49.0.0 (CIRISPersist#910.1, V154) — the family PK carries the
        // instant too: an EXACT repeat is the #861 no-op.
        for at in [first, first] {
            b.put_family_membership_revocation(ts::sign_family_membership_revocation(
                bob, /* v49.0.0 (#910): the member leaves on their own signature */
                crate::federation::types::FamilyMembershipRevocation {
                    family_key_id: fam.into(),
                    removed_identity_key_id: bob.into(),
                    removed_at: at,
                    effective_at: at,
                    reason: None,
                    witness_set: vec![],
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .expect("#861: a family removal and its repeat both return Ok");
        }
        let fam_rows = b.list_family_membership_revocations_for(fam).await.unwrap();
        assert_eq!(fam_rows.len(), 1);
        assert_eq!(
            fam_rows[0].removed_at.timestamp(),
            first.timestamp(),
            "the FIRST recorded family revocation stands — memory used to overwrite it"
        );
        // A removal at ANOTHER instant is another event, stored beside it.
        b.put_family_membership_revocation(ts::sign_family_membership_revocation(
            bob,
            crate::federation::types::FamilyMembershipRevocation {
                family_key_id: fam.into(),
                removed_identity_key_id: bob.into(),
                removed_at: now,
                effective_at: now,
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("a removal at another instant is admitted");
        assert_eq!(
            b.list_family_membership_revocations_for(fam)
                .await
                .unwrap()
                .len(),
            2,
            "#910.1: a removal at another instant is another row"
        );

        let epoch = || {
            b.test_query_i64("SELECT COALESCE(MAX(epoch), 0) FROM federation_community_dek_epoch")
        };
        // v48.0.0 (CIRISPersist#860, FSD §3.3) — the PK carries the instant:
        // an EXACT repeat is still the #861 no-op; a removal at another
        // instant is another event (a re-added member can be removed again).
        for at in [first, first] {
            b.put_community_membership_revocation(ts::sign_community_membership_revocation(
                bob, /* v49.0.0 (#908): the member leaves on their own signature */
                crate::federation::types::CommunityMembershipRevocation {
                    community_key_id: cid.into(),
                    removed_identity_key_id: bob.into(),
                    removed_at: at,
                    effective_at: at,
                    reason: None,
                    witness_set: vec![],
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .expect("#861: a community removal and its repeat both return Ok");
        }
        let after_both = epoch();
        let com_rows = b
            .list_community_membership_revocations_for(cid)
            .await
            .unwrap();
        assert_eq!(com_rows.len(), 1);
        assert_eq!(com_rows[0].removed_at.timestamp(), first.timestamp());
        assert!(
            after_both <= 1,
            "one removal, at most one rotation (got epoch {after_both})"
        );
    }

    /// v31.1.0 (CIRISPersist#665 review) — the MEMORY leg: **a refused
    /// replacement must not delete the row it was replacing.**
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    async fn refused_replacement_keeps_the_row_sqlite_665() {
        let backend = test_backend();
        backend
            .seed_genesis_accord_holders(crate::federation::genesis::accord_holder_genesis_records())
            .await
            .expect("holders seed");
        crate::federation::genesis::seed_family_and_canonical(&backend)
            .await
            .expect("seed the baked plane");
        crate::federation::genesis::assert_refused_replacement_keeps_the_row(&backend, "sqlite")
            .await;
    }

    /// v31.1.0 (CIRISPersist#665 review) — the MEMORY leg: **re-running the
    /// saved ceremony repairs the node's own ceremony row.**
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    async fn saved_ceremony_repairs_its_own_row_sqlite_665() {
        let backend = test_backend();
        backend
            .seed_genesis_accord_holders(crate::federation::genesis::accord_holder_genesis_records())
            .await
            .expect("holders seed");
        crate::federation::genesis::seed_family_and_canonical(&backend)
            .await
            .expect("seed the baked plane");
        // Thin the co-signature set beneath persist, leaving the signed
        // envelope — and therefore the bound instants — byte-identical.
        {
            let target = &crate::federation::genesis::canonical_genesis_bundle().attestations[0]
                .attestation
                .attestation_id;
            backend
                .test_execute(&format!(
                    "UPDATE federation_attestations SET additional_scrubs = '[]' \
                     WHERE attestation_id = '{target}'"
                ))
                .await;
        }
        crate::federation::genesis::assert_saved_ceremony_repairs_its_own_row(&backend, "sqlite")
            .await;
    }

    /// v31.1.0 (CIRISPersist#665 review) — the MEMORY leg: **a lost bake race
    /// must not be reported as success.**
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    async fn lost_bake_race_is_not_reported_as_success_sqlite_665() {
        let backend = test_backend();
        backend
            .seed_genesis_accord_holders(crate::federation::genesis::accord_holder_genesis_records())
            .await
            .expect("holders seed");
        crate::federation::genesis::seed_family_and_canonical(&backend)
            .await
            .expect("the winner installs the current plane");
        crate::federation::genesis::assert_lost_bake_race_is_not_reported_as_success(
            &backend, "sqlite",
        )
        .await;
    }

    /// v31.1.0 (CIRISPersist#665 review) — **a forged holder claim must not
    /// drain the reserve.** Backend-independent (the quota is shared code), so
    /// it is asserted once rather than three times.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[test]
    fn forged_genesis_claim_spares_the_reserve_665() {
        crate::federation::genesis::assert_forged_genesis_claim_spares_the_reserve("shared");
    }

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
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
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

    /// Register a key with a chosen `identity_type` (e.g. `user` / `witness` /
    /// `agent` / `node`).
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
        let err = backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .expect_err(
                "a self-asserted witness must NOT be able to assert an age rung about a \
                 third party — that is CIRISPersist#607",
            );
        let msg = err.to_string();
        assert!(
            msg.contains("infra:attest_assurance"),
            "the refusal must name the missing conferral so an operator knows what to obtain; \
             got: {msg}"
        );
    }

    async fn put_conferred_key(backend: &SqliteBackend, key_id: &str, it: &str, scope: &str) {
        use crate::federation::trust_root::{
            TRUST_ACCEPTS_DIMENSION, TRUST_CHARTER_DIMENSION, TRUST_CONFERS_DIMENSION,
        };
        let node = "n607-node";
        let root = "n607-root";
        backend.set_node_key_id(node);
        for k in [node, root] {
            put_typed_key(backend, k, "node").await;
        }
        put_typed_key(backend, key_id, it).await;
        // The root charters itself (key root), this node accepts it, and it
        // confers `scope` on the emitter.
        //
        // v38.5.0 (#771) — rows already placed by an earlier conferral in
        // this test are SKIPPED below, not re-offered: their ids are derived
        // and stable while `asserted_at` is not.
        for (id, from, to, dim, sc) in [
            // The root charters ITSELF (key root). It must carry a
            // pre_rotation_commitment: without a pre-committed successor set,
            // root-key compromise is unrecoverable by construction.
            // The charter's job dimension is trust:CHARTER:v1 — not
            // trust:confers. A charter is a root declaring itself, which is a
            // different job from conferring on someone else.
            (
                "n607-charter",
                root,
                root,
                TRUST_CHARTER_DIMENSION,
                "infra:serve",
            ),
            (
                "n607-accept",
                node,
                root,
                TRUST_ACCEPTS_DIMENSION,
                "infra:serve",
            ),
            ("n607-confer", root, key_id, TRUST_CONFERS_DIMENSION, scope),
        ] {
            // Sign the envelope we actually ship. Building the row first and
            // overwriting the envelope afterwards invalidates the signature —
            // the row then fails hybrid verify at the door, which is the door
            // working correctly on a fixture that lied.
            // A KEY-ROOT charter must carry BOTH infra:serve AND infra:attest
            // (the RC3 AND-minimum, #488) — one alone is not a charter.
            let mut envelope = if id == "n607-charter" {
                serde_json::json!({"dimension": dim, "scope": ["infra:serve", "infra:attest"]})
            } else {
                serde_json::json!({"dimension": dim, "scope": [sc]})
            };
            if id == "n607-charter" {
                envelope["pre_rotation_commitment"] =
                    serde_json::json!(crate::federation::trust_root::test_pre_rotation_commitment(
                        &["n607-root-successor".to_owned()]
                    )
                    .expect("commitment"));
            }
            let envelope = envelope;
            // v38.5.0 (#771) — skip what an earlier conferral in this test
            // already placed, rather than re-offering it with a fresh
            // `asserted_at` under the same derived id.
            if crate::federation::FederationDirectory::get_attestation(backend, id)
                .await
                .ok()
                .flatten()
                .is_some()
            {
                continue;
            }
            let mut a = fix_attestation(id, from, to, from);
            a.attestation_type =
                crate::federation::types::attestation_type::DELEGATES_TO.to_owned();
            a.attestation_envelope = envelope;
            a.scrub_key_id = from.to_owned();
            // v31.2.0 (CIRISPersist#670) — the seal has ONE home. This used to
            // call `sign_envelope` and assign the hash and both signature
            // halves by hand, and then call `reseal`, which recomputed all
            // three from the same signer — the hand-rolled copy was dead the
            // moment it was written. Dead is the lucky outcome of that shape;
            // #643's `pg_resign` is the same code that was NOT overwritten,
            // and it signed every postgres fixture without its instants.
            crate::federation::tier_ingest::test_support::reseal(&mut a);
            match backend
                .put_attestation(crate::federation::SignedAttestation { attestation: a })
                .await
            {
                Ok(_) => {}
                // v38.5.0 (CIRISPersist#771) — see the twin in
                // `admission.rs`: this "idempotence" was a DIFFERENT row
                // (fresh `asserted_at`) under a derived id, silently
                // discarded. The fixture now skips what it already placed.
                Err(e) => panic!("conferral edge must admit: {e}"),
            }
        }
    }

    async fn put_typed_key(backend: &SqliteBackend, key_id: &str, it: &str) {
        let mut rec = fix_key(key_id, "ref", key_id);
        rec.identity_type = it.to_owned();
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .unwrap();
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

    /// age_band resolution: witness adult OUTRANKS self minor; self minor
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
            age_band(&backend, "ab-subj").await.unwrap(),
            AgeBand::Unknown
        );

        // Self-declared adult alone → Unknown (the one-way ratchet ignores a
        // self-declared adult).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "ab-self-adult",
                    "ab-subj",
                    "ab-subj",
                    "age_self_declared:band:adult",
                ),
            })
            .await
            .unwrap();
        assert_eq!(
            age_band(&backend, "ab-subj").await.unwrap(),
            AgeBand::Unknown,
            "a self-declared adult must NOT graduate the subject to Adult",
        );

        // Add a self-declared MINOR → Minor (a subject may ratchet DOWN).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "ab-self-minor",
                    "ab-subj",
                    "ab-subj",
                    "age_self_declared:band:minor",
                ),
            })
            .await
            .unwrap();
        assert_eq!(age_band(&backend, "ab-subj").await.unwrap(), AgeBand::Minor);

        // A witness ADULT attestation OUTRANKS the self-declared minor → Adult.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "ab-witness-adult",
                    "ab-witness",
                    "ab-subj",
                    "age_assurance:provider:adult:v1",
                ),
            })
            .await
            .unwrap();
        assert_eq!(
            age_band(&backend, "ab-subj").await.unwrap(),
            AgeBand::Adult,
            "the witness rung must outrank a self-declared minor",
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
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "abe-w-minor",
                    "abe-witness",
                    "abe-subj",
                    "age_assurance:provider:minor:v1",
                ),
            })
            .await
            .unwrap();
        assert_eq!(
            age_band(&backend, "abe-subj").await.unwrap(),
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
        resign_fix(&mut expired);
        backend
            .put_attestation(SignedAttestation {
                attestation: expired,
            })
            .await
            .unwrap();
        assert_eq!(
            age_band(&backend, "abe-subj").await.unwrap(),
            AgeBand::Minor,
            "an expired witness adult must be ignored (liveness = expires_at)",
        );
    }

    /// CC 3.2 user-target gate decision table, exercised through the REAL
    /// `put_attestation` admission path on the memory backend.
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
            backend
                .put_attestation(SignedAttestation {
                    attestation: fix_age_attestation(id, "ut-witness", subj, token),
                })
                .await
                .unwrap();
        }

        let deleg = |id: &str, s: &str, t: &str| {
            fix_owner_binding_delegates_to(id, s, t, s, &[ds::INFRA_SERVE])
        };

        // S(adult user) → A(adult user) : REJECTED (target_is_self_sovereign).
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: deleg("utd-A", "ut-S", "ut-A"),
            })
            .await
            .unwrap_err();
        assert_eq!(e.kind(), "federation_user_target_steward_binding_forbidden");
        match e {
            crate::federation::Error::UserTargetStewardBindingForbidden { reason, .. } => {
                assert_eq!(reason, "target_is_self_sovereign");
            }
            other => panic!("expected UserTargetStewardBindingForbidden, got {other:?}"),
        }

        // S(adult) → U(no age = Unknown) : REJECTED (target_age_unverified).
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: deleg("utd-U", "ut-S", "ut-U"),
            })
            .await
            .unwrap_err();
        match e {
            crate::federation::Error::UserTargetStewardBindingForbidden { reason, .. } => {
                assert_eq!(reason, "target_age_unverified");
            }
            other => panic!("expected UserTargetStewardBindingForbidden, got {other:?}"),
        }

        // S(adult user) → M(witness minor) : ADMITTED (legal guardianship).
        backend
            .put_attestation(SignedAttestation {
                attestation: deleg("utd-M", "ut-S", "ut-M"),
            })
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

        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "ugw-M",
                    "ug-witness",
                    "ug-M",
                    "age_assurance:provider:minor:v1",
                ),
            })
            .await
            .unwrap();

        // U(unknown-age user) → M(minor) : REJECTED (granter not proven adult).
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding_delegates_to(
                    "ugd-UM",
                    "ug-U",
                    "ug-M",
                    "ug-U",
                    &[ds::INFRA_SERVE],
                ),
            })
            .await
            .unwrap_err();
        match e {
            crate::federation::Error::UserTargetStewardBindingForbidden { reason, .. } => {
                assert_eq!(reason, "granter_not_adult_user");
            }
            other => panic!("expected UserTargetStewardBindingForbidden, got {other:?}"),
        }

        // U(unknown-age user) → N(node) : the user-target gate is a no-op for a
        // node target (infra:* scope clears the node-agency gate) → ADMITTED.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding_delegates_to(
                    "ugd-UN",
                    "ug-U",
                    "ug-N",
                    "ug-U",
                    &[ds::INFRA_SERVE],
                ),
            })
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

        // Baseline: T self-declares MINOR (the non-reserved self rung still
        // admits attester==attested — it is subject-signed by design).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "wts-self-minor",
                    "wts-T",
                    "wts-T",
                    "age_self_declared:band:minor:v1",
                ),
            })
            .await
            .expect("subject-signed self rung admits");
        assert_eq!(age_band(&backend, "wts-T").await.unwrap(), AgeBand::Minor);

        // CROSS-SUBJECT witness graduation: W attests T adult — ADMITTED, and
        // T's band graduates (witness outranks T's own self-declared minor).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "wts-w-adult",
                    "wts-witness",
                    "wts-T",
                    "age_assurance:government:adult:v1",
                ),
            })
            .await
            .expect("witness-targets-subject age_assurance is admitted (CC 3.4.13)");
        assert_eq!(
            age_band(&backend, "wts-T").await.unwrap(),
            AgeBand::Adult,
            "a witness row ABOUT T graduates T's band",
        );
        assert_eq!(
            age_band_fine(&backend, "wts-T").await.unwrap(),
            AgeBandFine::Adult,
            "the finer resolution graduates too",
        );

        // SELF-graduation via the witness prefix: W attests W — REJECTED
        // (attester == attested; CC 3.4.11 "a subject MUST NOT emit on
        // `age_assurance:`"). The witness identity_type does NOT bypass.
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "wts-w-self",
                    "wts-witness",
                    "wts-witness",
                    "age_assurance:provider:adult:v1",
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(e.kind(), "federation_age_assurance_self_emission_rejected");
        assert_eq!(
            age_band(&backend, "wts-witness").await.unwrap(),
            AgeBand::Unknown,
            "the rejected self-emission confers nothing",
        );

        // Identity gate UNCHANGED: a plain user cross-attesting T's age is
        // still refused (reserved prefix requires a witness emitter).
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "wts-p-cross",
                    "wts-P",
                    "wts-T",
                    "age_assurance:provider:minor:v1",
                ),
            })
            .await
            .unwrap_err();
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
            age_band(&backend, "pg-witness").await.unwrap(),
            AgeBand::Unknown,
            "a pre-gate self-emitted witness row is skipped at read time",
        );
        assert_eq!(
            age_band_fine(&backend, "pg-witness").await.unwrap(),
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
        assert_eq!(age_band(&backend, "pg-T").await.unwrap(), AgeBand::Adult);
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

    fn assert_forbidden(e: &crate::federation::Error, want: &str) {
        assert_eq!(e.kind(), "federation_user_target_steward_binding_forbidden");
        match e {
            crate::federation::Error::UserTargetStewardBindingForbidden { reason, .. } => {
                assert_eq!(*reason, want, "wrong rejection reason");
            }
            other => panic!("expected UserTargetStewardBindingForbidden({want}), got {other:?}"),
        }
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
            backend
                .put_attestation(SignedAttestation {
                    attestation: fix_age_attestation(
                        &format!("{p}w-{who}"),
                        &format!("{p}-assessor"),
                        &format!("{p}-{who}"),
                        "age_assurance:provider:adult:v1",
                    ),
                })
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
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(id, attester, ward, token),
            })
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
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "cap-ok",
                    "cap-assessor",
                    "cap-subj",
                    "capacity_assurance:panel:financial:incapacitated:v1",
                ),
            })
            .await
            .expect("witness assessor may attest another's capacity");

        // A non-witness (plain user) may NOT emit capacity_assurance.
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "cap-nonwit",
                    "cap-user",
                    "cap-subj",
                    "capacity_assurance:provider:medical:incapacitated:v1",
                ),
            })
            .await
            .unwrap_err();
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
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "cap-self",
                    "cap-selfwit",
                    "cap-selfwit",
                    "capacity_assurance:provider:financial:incapacitated:v1",
                ),
            })
            .await
            .unwrap_err();
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
        let future = (Utc::now() + Duration::days(30)).to_rfc3339();

        // (0) presumption of capacity — an adult with NO incapacity attested is
        // self-sovereign (the CC 3.2 un-stewardable default reasserts).
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "ai-0",
                    "ai-S",
                    "ai-A",
                    &["financial"],
                    Some("prior_will_proxy"),
                    Some(&future),
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
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
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "ai-1",
                    "ai-S",
                    "ai-A",
                    &["financial"],
                    None,
                    Some(&future),
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_forbidden(&e, "missing_legitimacy_source");

        // (2) missing valid_until → no fail-to-liberty expiry.
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "ai-2",
                    "ai-S",
                    "ai-A",
                    &["financial"],
                    Some("prior_will_proxy"),
                    None,
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_forbidden(&e, "missing_valid_until");

        // (3) valid_until beyond the T2 review cadence (90d) → rejected.
        let far = (Utc::now() + Duration::days(200)).to_rfc3339();
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "ai-3",
                    "ai-S",
                    "ai-A",
                    &["financial"],
                    Some("prior_will_proxy"),
                    Some(&far),
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_forbidden(&e, "valid_until_exceeds_review_cadence");

        // (4) scope exceeds the attested-incapacitated domains.
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "ai-4",
                    "ai-S",
                    "ai-A",
                    &["medical"],
                    Some("prior_will_proxy"),
                    Some(&future),
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
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
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "ai-5",
                    "ai-S",
                    "ai-A",
                    &["residence"],
                    Some("prior_will_proxy"),
                    Some(&future),
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_forbidden(&e, "capacity_reversible_not_excluded");

        // (6) ADMIT — scope ⊆ attested loss, reversible excluded, prior-will
        // legitimacy, bounded valid_until, independent assessor.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "ai-6",
                    "ai-S",
                    "ai-A",
                    &["financial"],
                    Some("prior_will_proxy"),
                    Some(&future),
                    None,
                    None,
                ),
            })
            .await
            .expect("valid adult-incapacity binding is admitted");

        // A live binding makes S an anchor of A; A (an adult) also self-anchors
        // (it is never demoted to a perpetual minor).
        let anchors = steward_bindings_of(&backend, "ai-A").await.unwrap();
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
        let soon = (Utc::now() + Duration::days(2)).to_rfc3339();
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
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "t1-std",
                    "t1-S",
                    "t1-A",
                    &["medical"],
                    Some(legitimacy_source::PRIOR_WILL_PROXY),
                    Some(&soon),
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_forbidden(&e, "capacity_reversible_not_excluded");

        // T1 acute path → admitted.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "t1-ok",
                    "t1-S",
                    "t1-A",
                    &["medical"],
                    Some(legitimacy_source::EMERGENCY_NECESSITY_EXPEDITED),
                    Some(&soon),
                    Some(tier::T1_EMERGENCY_NECESSITY),
                    None,
                ),
            })
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
        let future = (Utc::now() + Duration::days(10)).to_rfc3339();
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
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "pd-b",
                    "pd-S",
                    "pd-A",
                    &["voting"],
                    Some("wa_due_process_quorum"),
                    Some(&future),
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
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
        let future = (Utc::now() + Duration::days(10)).to_rfc3339();
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
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "cf-b",
                    "cf-S",
                    "cf-A",
                    &["financial"],
                    Some("wa_due_process_quorum"),
                    Some(&future),
                    None,
                    Some("cf-assessor"),
                ),
            })
            .await
            .unwrap_err();
        assert_forbidden(&e, "attester_conflicted");
    }

    /// CC 3.4.12 fail-to-liberty: a binding whose `valid_until` has lapsed is
    /// non-live — the steward drops out of the ward's anchors and the adult
    /// auto-re-sovereigns (self-anchor only), with NO steward assent.
    #[tokio::test]
    async fn adult_incapacity_fail_to_liberty_auto_re_sovereign() {
        use crate::federation::admission::steward_bindings_of;
        use chrono::{Duration, Utc};
        let backend = test_backend();
        bootstrap_incapacity(&backend, "fl").await;
        put_capacity(
            &backend,
            "flc",
            "fl-assessor",
            "fl-A",
            "capacity_assurance:panel:financial:incapacitated:v1",
        )
        .await;
        put_capacity(
            &backend,
            "flc-rex",
            "fl-assessor",
            "fl-A",
            "capacity_assurance:reversible_excluded:financial:v1",
        )
        .await;
        // Admit a binding whose valid_until is ALREADY in the past (structurally
        // admissible: present, parseable, within the cadence ceiling).
        let lapsed = (Utc::now() - Duration::days(1)).to_rfc3339();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "fl-b",
                    "fl-S",
                    "fl-A",
                    &["financial"],
                    Some("prior_will_proxy"),
                    Some(&lapsed),
                    None,
                    None,
                ),
            })
            .await
            .expect("a lapsed-valid_until binding is structurally admitted");

        // Fail-to-liberty at READ: the lapsed edge confers no standing. S is
        // NOT an anchor; the adult self-anchors (auto-re-sovereign).
        let anchors = steward_bindings_of(&backend, "fl-A").await.unwrap();
        assert!(
            !anchors.contains(&"fl-S".to_string()),
            "a lapsed adult-incapacity binding must NOT confer steward standing"
        );
        assert_eq!(
            anchors,
            vec!["fl-A".to_string()],
            "the adult auto-re-sovereigns to its own self-anchor with no steward assent"
        );
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
            backend
                .put_attestation(SignedAttestation {
                    attestation: fix_age_attestation(id, "ml-witness", subj, token),
                })
                .await
                .unwrap();
        }

        // An adult user with no edge self-anchors (sovereign — its own steward).
        assert!(
            is_steward_bound(&backend, "ml-A").await.unwrap(),
            "an adult user is its own steward anchor",
        );

        // A steward-less minor does NOT self-anchor (fail-secure).
        assert!(
            !is_steward_bound(&backend, "ml-M").await.unwrap(),
            "a steward-less minor must NOT self-anchor (CC 3.2 fail-secure)",
        );

        // Bind the minor to the adult steward (live edge) → steward-bound.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding_delegates_to(
                    "ml-bind",
                    "ml-S",
                    "ml-M",
                    "ml-S",
                    &[ds::INFRA_SERVE],
                ),
            })
            .await
            .expect("adult-user steward → minor ward admitted");
        assert!(is_steward_bound(&backend, "ml-M").await.unwrap());
        assert_eq!(
            steward_bindings_of(&backend, "ml-M").await.unwrap(),
            vec!["ml-S".to_string()],
            "while bound, the minor is anchored only to the adult steward (NOT self)",
        );

        // The adult withdraws the binding → the minor fails secure again.
        let mut w = fix_attestation("ml-withdraw", "ml-S", "ml-M", "ml-S");
        w.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.into();
        w.attestation_envelope = serde_json::json!({ "id": "ml-withdraw" });
        resign_fix(&mut w);
        backend
            .put_attestation(SignedAttestation { attestation: w })
            .await
            .unwrap();
        assert!(
            !is_steward_bound(&backend, "ml-M").await.unwrap(),
            "a minor whose only adult steward was withdrawn must be steward-less (fail-secure)",
        );
        assert!(steward_bindings_of(&backend, "ml-M")
            .await
            .unwrap()
            .is_empty());

        // Control: a node bound then withdrawn is unchanged (bound→true,
        // withdrawn→false) — the node path never used clauses (1)/(2).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding_delegates_to(
                    "ml-nbind",
                    "ml-S",
                    "ml-N",
                    "ml-S",
                    &[ds::INFRA_SERVE],
                ),
            })
            .await
            .unwrap();
        assert!(is_steward_bound(&backend, "ml-N").await.unwrap());
        let mut wn = fix_attestation("ml-nwithdraw", "ml-S", "ml-N", "ml-S");
        wn.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.into();
        wn.attestation_envelope = serde_json::json!({ "id": "ml-nwithdraw" });
        resign_fix(&mut wn);
        backend
            .put_attestation(SignedAttestation { attestation: wn })
            .await
            .unwrap();
        assert!(
            !is_steward_bound(&backend, "ml-N").await.unwrap(),
            "the node/agent fail-secure path is unchanged by the minor gate",
        );
    }

    // ─── v21.0.0 (CIRISPersist#502 E4) — keyless-declaration forgery
    //     witnesses. `Family` / `Community` / `FamilyMembershipRevocation` /
    //     `CommunityMembershipRevocation` / `LocationProof` carried NO
    //     per-record signature at all (admission was FK-existence only), so
    //     any linked peer could forge one wholesale — worst case, a forged
    //     community-membership removal rotates the CC 4.4.3.2.2 DEK epoch
    //     (an unauthenticated forward-secrecy DoS). Each witness below: an
    //     honestly-signed record admits; the SAME record re-signed by a
    //     DIFFERENT key (while still CLAIMING the honest authority's
    //     `authority_key_id`) is rejected fail-closed and leaves no trace.

    /// A forged `Family`: claims `authority_key_id: "e4-fam-authority"` but
    /// the envelope is actually signed by `e4-fam-attacker`'s key — the
    /// registered pubkeys of the claimed authority won't verify it.
    #[tokio::test]
    async fn forged_family_wrong_signer_rejected_502e4() {
        let backend = test_backend();
        for k in [
            "e4-fam-authority",
            "e4-fam-attacker",
            "e4-fam-member",
            "e4-fam-good",
            "e4-fam-forged",
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "ref", k),
                })
                .await
                .unwrap();
        }
        let fam = |key_id: &str| crate::federation::types::Family {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            family_key_id: key_id.into(),
            family_name: "E4 Household".into(),
            members: vec![crate::federation::types::FamilyMember {
                key_id: "e4-fam-member".into(),
                joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                role: None,
            }],
            founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            consensus_protocol: "founder_only".into(),
            consensus_protocol_entrenched: false,
            dissolved_at: None,
            persist_row_hash: String::new(),
        };
        // Honest: signed by the authority it claims to be — admits.
        backend
            .put_family(crate::federation::tier_ingest::test_support::sign_family(
                "e4-fam-authority",
                fam("e4-fam-good"),
            ))
            .await
            .expect("(E4) honestly-signed family admits");

        // Forged: same shape, but the SIGNATURE comes from the attacker's
        // key while `authority_key_id` still claims the honest authority.
        let mut forged = crate::federation::tier_ingest::test_support::sign_family(
            "e4-fam-attacker",
            fam("e4-fam-forged"),
        );
        forged.authority_key_id = "e4-fam-authority".to_owned();
        let err = backend
            .put_family(forged)
            .await
            .expect_err("(E4) forged family must be rejected");
        assert!(
            err.kind().contains("federation_tier_unverified") || err.kind().contains("unverified"),
            "rejected by hybrid verify, got kind {}",
            err.kind()
        );
        assert!(
            backend
                .lookup_family("e4-fam-forged")
                .await
                .unwrap()
                .is_none(),
            "(E4) rejected family must NOT be stored (fail-secure)"
        );
    }

    /// A forged `Community`: same shape as the family witness.
    #[tokio::test]
    async fn forged_community_wrong_signer_rejected_502e4() {
        let backend = test_backend();
        for k in [
            "e4-comm-authority",
            "e4-comm-attacker",
            "e4-comm-member",
            "e4-comm-good",
            "e4-comm-forged",
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "ref", k),
                })
                .await
                .unwrap();
        }
        let comm = |key_id: &str| crate::federation::types::Community {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            community_key_id: key_id.into(),
            community_name: "E4 Co-op".into(),
            members: vec![crate::federation::types::CommunityMember {
                key_id: "e4-comm-member".into(),
                joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                role: None,
            }],
            founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            consensus_protocol: "founder_only".into(),
            policy_blob: None,
            persist_row_hash: String::new(),
        };
        backend
            .put_community(
                crate::federation::tier_ingest::test_support::sign_community(
                    "e4-comm-authority",
                    comm("e4-comm-good"),
                ),
            )
            .await
            .expect("(E4) honestly-signed community admits");

        let mut forged = crate::federation::tier_ingest::test_support::sign_community(
            "e4-comm-attacker",
            comm("e4-comm-forged"),
        );
        forged.authority_key_id = "e4-comm-authority".to_owned();
        let err = backend
            .put_community(forged)
            .await
            .expect_err("(E4) forged community must be rejected");
        assert!(
            err.kind().contains("federation_tier_unverified") || err.kind().contains("unverified"),
            "rejected by hybrid verify, got kind {}",
            err.kind()
        );
        assert!(
            backend
                .lookup_community("e4-comm-forged")
                .await
                .unwrap()
                .is_none(),
            "(E4) rejected community must NOT be stored (fail-secure)"
        );
    }

    /// A forged `FamilyMembershipRevocation`.
    #[tokio::test]
    async fn forged_family_membership_revocation_wrong_signer_rejected_502e4() {
        let backend = test_backend();
        for k in [
            "e4-fmr-authority",
            "e4-fmr-attacker",
            "e4-fmr-fam",
            "e4-fmr-member",
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "ref", k),
                })
                .await
                .unwrap();
        }
        backend
            .put_family(crate::federation::tier_ingest::test_support::sign_family(
                "e4-fmr-fam",
                crate::federation::types::Family {
                    prev_head_digest: String::new(),
                    charter_digest: String::new(),
                    family_key_id: "e4-fmr-fam".into(),
                    family_name: "E4 FMR Household".into(),
                    members: vec![
                        crate::federation::types::FamilyMember {
                            key_id: "e4-fmr-member".into(),
                            joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                            role: None,
                        },
                        // v49.0.0 (#910): the honest authority has standing
                        // — it founds this `founder_only` family.
                        crate::federation::types::FamilyMember {
                            key_id: "e4-fmr-authority".into(),
                            joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                            role: Some(crate::federation::admission::MEMBER_ROLE_FOUNDER.into()),
                        },
                    ],
                    founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                    consensus_protocol: "founder_only".into(),
                    consensus_protocol_entrenched: false,
                    dissolved_at: None,
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .expect("seed family");

        let effective: chrono::DateTime<chrono::Utc> = "2026-06-10T00:00:00Z".parse().unwrap();
        let rev = crate::federation::FamilyMembershipRevocation {
            family_key_id: "e4-fmr-fam".into(),
            removed_identity_key_id: "e4-fmr-member".into(),
            removed_at: effective,
            effective_at: effective,
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        };
        // Honest: signed by e4-fmr-authority — admits.
        backend
            .put_family_membership_revocation(
                crate::federation::tier_ingest::test_support::sign_family_membership_revocation(
                    "e4-fmr-authority",
                    rev.clone(),
                ),
            )
            .await
            .expect("(E4) honestly-signed revocation admits");

        // Forged: a DIFFERENT removal (so it isn't a no-op re-submit),
        // signed by the attacker but claiming the honest authority.
        let forged_rev = crate::federation::FamilyMembershipRevocation {
            removed_identity_key_id: "e4-fmr-fam".into(), // different removal target
            ..rev
        };
        let mut forged =
            crate::federation::tier_ingest::test_support::sign_family_membership_revocation(
                "e4-fmr-attacker",
                forged_rev,
            );
        forged.authority_key_id = "e4-fmr-authority".to_owned();
        let err = backend
            .put_family_membership_revocation(forged)
            .await
            .expect_err("(E4) forged revocation must be rejected");
        assert!(
            err.kind().contains("federation_tier_unverified") || err.kind().contains("unverified"),
            "rejected by hybrid verify, got kind {}",
            err.kind()
        );
        assert!(
            backend
                .list_family_membership_revocations_for("e4-fmr-fam")
                .await
                .unwrap()
                .iter()
                .all(|r| r.removed_identity_key_id != "e4-fmr-fam"),
            "(E4) rejected revocation must NOT be stored (fail-secure)"
        );
    }

    /// A forged `CommunityMembershipRevocation` — THE worst-case E4 hole: an
    /// unverified removal rotates the CC 4.4.3.2.2 community DEK epoch, an
    /// unauthenticated forward-secrecy DoS.
    #[tokio::test]
    async fn forged_community_membership_revocation_wrong_signer_rejected_502e4() {
        let backend = test_backend();
        for k in [
            "e4-cmr-authority",
            "e4-cmr-attacker",
            "e4-cmr-comm",
            "e4-cmr-member",
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "ref", k),
                })
                .await
                .unwrap();
        }
        backend
            .put_community(
                // v49.0.0 (#908) — the real authority is the room's record
                // signer, so its honest removal has standing.
                crate::federation::tier_ingest::test_support::sign_community(
                    "e4-cmr-authority",
                    crate::federation::types::Community {
                        prev_head_digest: String::new(),
                        charter_digest: String::new(),
                        community_key_id: "e4-cmr-comm".into(),
                        community_name: "E4 CMR Co-op".into(),
                        members: vec![crate::federation::types::CommunityMember {
                            key_id: "e4-cmr-member".into(),
                            joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                            role: None,
                        }],
                        founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                        consensus_protocol: "founder_only".into(),
                        policy_blob: None,
                        persist_row_hash: String::new(),
                    },
                ),
            )
            .await
            .expect("seed community");
        assert_eq!(backend.community_dek_epoch("e4-cmr-comm"), 0);

        let effective: chrono::DateTime<chrono::Utc> = "2026-06-10T00:00:00Z".parse().unwrap();
        // Forged FIRST: signed by the attacker but claiming the honest
        // authority — must be rejected BEFORE the epoch bump.
        let forged_rev = crate::federation::CommunityMembershipRevocation {
            community_key_id: "e4-cmr-comm".into(),
            removed_identity_key_id: "e4-cmr-member".into(),
            removed_at: effective,
            effective_at: effective,
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        };
        let mut forged =
            crate::federation::tier_ingest::test_support::sign_community_membership_revocation(
                "e4-cmr-attacker",
                forged_rev,
            );
        // v49.0.0 (#908): the honest authority is the member leaving.
        forged.authority_key_id = "e4-cmr-member".to_owned();
        let err = backend
            .put_community_membership_revocation(forged)
            .await
            .expect_err("(E4) forged community removal must be rejected");
        assert!(
            err.kind().contains("federation_tier_unverified") || err.kind().contains("unverified"),
            "rejected by hybrid verify, got kind {}",
            err.kind()
        );
        assert_eq!(
            backend.community_dek_epoch("e4-cmr-comm"),
            0,
            "(E4) a forged removal must NOT rotate the DEK epoch (forward-secrecy DoS closed)"
        );
        assert!(
            backend
                .list_community_membership_revocations_for("e4-cmr-comm")
                .await
                .unwrap()
                .is_empty(),
            "(E4) rejected removal must NOT be stored (fail-secure)"
        );

        // Honest, same content, signed by the real authority — admits +
        // bumps the epoch.
        let honest_rev = crate::federation::CommunityMembershipRevocation {
            community_key_id: "e4-cmr-comm".into(),
            removed_identity_key_id: "e4-cmr-member".into(),
            removed_at: effective,
            effective_at: effective,
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        };
        backend
            .put_community_membership_revocation(
                crate::federation::tier_ingest::test_support::sign_community_membership_revocation(
                    "e4-cmr-member",
                    honest_rev,
                ),
            )
            .await
            .expect("(E4) honestly-signed removal admits");
        assert_eq!(backend.community_dek_epoch("e4-cmr-comm"), 1);
    }

    /// A forged `LocationProof`.
    #[tokio::test]
    async fn forged_location_proof_wrong_signer_rejected_502e4() {
        let backend = test_backend();
        for k in ["e4-loc-authority", "e4-loc-attacker", "e4-loc-subject"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "ref", k),
                })
                .await
                .unwrap();
        }
        let cell7 = h3o::LatLng::new(37.0, -122.0)
            .unwrap()
            .to_cell(h3o::Resolution::Seven)
            .to_string();
        let proof = |asserted_at: &str| crate::federation::types::LocationProof {
            subject_key_id: "e4-loc-subject".into(),
            cell_id: cell7.clone(),
            cell_resolution: 7,
            asserted_at: asserted_at.parse().unwrap(),
            valid_until: None,
            attestation_evidence: None,
            withdrawn_at: None,
            persist_row_hash: String::new(),
        };
        // Honest: signed by the SUBJECT itself — admits.
        //
        // v37.0.0 (CIRISPersist#734) — this used to be signed by
        // `e4-loc-authority`, an unrelated registered third party, and it
        // admitted. That WAS the #734 hole, asserted as correct behaviour by
        // this very test: E4 only ever checked that the signature matched the
        // offered authority's registered pubkeys, never that the authority had
        // standing over the subject. The honest signer is the subject now.
        // `e4-loc-authority` stays registered because the forgery below claims
        // to be it, and the leg is only meaningful against a key that resolves.
        backend
            .put_location_proof(
                crate::federation::tier_ingest::test_support::sign_location_proof(
                    "e4-loc-subject",
                    proof("2026-06-01T00:00:00Z"),
                ),
            )
            .await
            .expect("(E4) honestly-signed location proof admits");

        // Forged: a DIFFERENT proof (distinct asserted_at, so it isn't a
        // no-op re-submit), signed by the attacker, claiming the subject's
        // own key as authority. The SIGNATURE leg must catch this — which is
        // what keeps it distinct from the #734 authority leg, and why the
        // claimed authority is the one that WOULD have had standing.
        let mut forged = crate::federation::tier_ingest::test_support::sign_location_proof(
            "e4-loc-attacker",
            proof("2026-06-02T00:00:00Z"),
        );
        forged.authority_key_id = "e4-loc-subject".to_owned();
        let err = backend
            .put_location_proof(forged)
            .await
            .expect_err("(E4) forged location proof must be rejected");
        assert!(
            err.kind().contains("federation_tier_unverified") || err.kind().contains("unverified"),
            "rejected by hybrid verify, got kind {}",
            err.kind()
        );
        let rows = backend
            .list_location_proofs_for("e4-loc-subject")
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "(E4) rejected proof must NOT be stored (fail-secure)"
        );
        assert_eq!(
            rows[0].asserted_at,
            "2026-06-01T00:00:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap()
        );
    }

    // ─── v21.0.0 (CIRISPersist#502 E4 followup) — the authority signature
    //     E4's admission gate verifies must be PERSISTED, not verified-then-
    //     discarded: before this cut, `Family`/`Community`/etc. had no home
    //     for `authority_key_id` / `scrub_signature_{classical,pqc}`, so the
    //     durable row could never prove its own authorship. Put an
    //     authority-signed family, then read the stored side-map entry
    //     directly (there is no public reconstruction of `SignedFamily` on
    //     the read side yet — see the V110 migration note) and assert all 3
    //     fields round-trip byte-exact.

    // ── v31.0.0 (CIRISPersist#656) — the ungated-door witnesses, MEMORY legs ──
    //
    // Each is three lines over a shared body in `admission`, because every one
    // of these findings was a door that had a gate on some backends (or some
    // doors) and not others. A witness written into ONE backend's test module
    // is how that class comes back.
}
