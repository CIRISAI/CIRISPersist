//! v47.1.0 (CIRISPersist#844) — **a trace's admission instant is readable
//! and filterable per trace**, not only table-wide.
//!
//! #606 gave `trace_events` an `admitted_at` (when THIS node accepted the
//! trace) and surfaced it table-wide as `newest_admitted_at`. CIRISServer's
//! per-agent receipt (CIRISServer#592) needs it per trace: "did my run's
//! traces land in the last two minutes" is a question about admission, and a
//! producer whose clock is skewed, or that replays older traces, answers it
//! wrong on `started_at`.
//!
//! I148 is the backfill shape #606's witness uses: traces a YEAR old by the
//! producer's clock, admitted now. The two windows must disagree, each must be
//! right about its own question, and the list and the count must agree with
//! each other under the same filter.

/// The I148 body, one per backend runner.
#[cfg(any(test, feature = "test-anchor"))]
pub mod bodies {
    use crate::read::{TimeWindow, TraceFilter};
    use crate::scope::CallerScope;

    fn row(
        trace_id: &str,
        agent: &str,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> crate::store::TraceEventRow {
        crate::store::TraceEventRow {
            trace_id: trace_id.to_owned(),
            thought_id: format!("th-{trace_id}"),
            task_id: None,
            step_point: None,
            event_type: crate::schema::ReasoningEventType::ActionResult,
            attempt_index: 0,
            ts,
            agent_name: None,
            agent_id_hash: agent.to_owned(),
            cognitive_state: None,
            trace_level: crate::schema::TraceLevel::Generic,
            payload: serde_json::Map::new(),
            cost_llm_calls: None,
            cost_tokens: None,
            cost_usd: None,
            signature: "c2ln".to_owned(),
            signing_key_id: "k1".to_owned(),
            signature_verified: true,
            verification_source: crate::store::VerificationSource::Persist,
            schema_version: "2.7.0".to_owned(),
            pii_scrubbed: false,
            agent_role: None,
            agent_template: None,
            deployment_domain: None,
            deployment_type: None,
            deployment_region: None,
            deployment_trust_mode: None,
            original_content_hash: None,
            scrub_signature: None,
            scrub_key_id: None,
            scrub_timestamp: None,
            // The backend stamps its own instant; a caller-supplied one must
            // not survive (#606).
            admitted_at: None,
            scrub_ner_ran: None,
            scrub_applied_trace_level: None,
            scrub_model_digest: None,
            cohort_scope: "federation".to_owned(),
            cohort_target_id: None,
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
        }
    }

    /// **I148 — the admission window and the per-trace admission instant.**
    pub async fn i148_admission_is_per_trace_and_filterable<B>(b: &B, s: &str)
    where
        B: crate::store::Backend + crate::ceg::ReadEngine + Sync,
    {
        let agent = format!("i148-agent-{s}");
        let other = format!("i148-other-{s}");
        let year_ago = chrono::Utc::now() - chrono::Duration::days(365);
        let before = chrono::Utc::now() - chrono::Duration::seconds(1);
        let rows = [
            row(&format!("i148-a-{s}"), &agent, year_ago),
            row(
                &format!("i148-b-{s}"),
                &agent,
                year_ago + chrono::Duration::minutes(1),
            ),
            row(&format!("i148-c-{s}"), &other, year_ago),
        ];
        b.insert_trace_events_batch(&rows)
            .await
            .unwrap_or_else(|e| panic!("I148: insert: {e}"));
        let after = chrono::Utc::now() + chrono::Duration::seconds(1);

        let list = |f: TraceFilter| async move {
            crate::ceg::ReadEngine::list_trace_summaries(
                b,
                f,
                None,
                100,
                CallerScope::Unauthenticated,
            )
            .await
            .unwrap_or_else(|e| panic!("I148: list: {e}"))
            .items
        };
        let count = |f: TraceFilter| async move {
            crate::ceg::ReadEngine::count_traces(b, f, CallerScope::Unauthenticated)
                .await
                .unwrap_or_else(|e| panic!("I148: count: {e}"))
        };
        let win = |a, z| Some(TimeWindow::new(a, z).unwrap());
        let mine = |w_started, w_admitted| TraceFilter {
            agent_id_hash: Some(agent.clone()),
            time_window: w_started,
            admitted_window: w_admitted,
            ..Default::default()
        };

        // 1 — the PRODUCER's clock says a year ago: the started window for
        // "the last minute" holds nothing, which is exactly how a live-test
        // verdict read on `started_at` goes wrong.
        let recent = win(before, after);
        assert!(
            list(mine(recent, None)).await.is_empty(),
            "I148/1: `time_window` is the producer's clock — year-old traces are not recent by it"
        );

        // 2 — THIS NODE's clock says just now: the admission window holds
        // both of the agent's traces, AND-composed with the agent filter (the
        // other agent's trace, admitted in the same batch, is not here).
        let got = list(mine(None, recent)).await;
        assert_eq!(
            got.len(),
            2,
            "I148/2: the admission window holds what this node admitted in it, for this agent"
        );
        for t in &got {
            let at = t.admitted_at.unwrap_or_else(|| {
                panic!(
                    "I148/2: {} carries no admitted_at, but this node just admitted it",
                    t.trace_id
                )
            });
            assert!(
                at >= before && at < after,
                "I148/2: {} admitted_at {at} is outside the window it was selected by",
                t.trace_id
            );
            assert!(
                t.started_at < before,
                "I148/2: started_at stays the producer's claim"
            );
        }

        // 3 — ONE predicate, two consumers: the count agrees with the list.
        assert_eq!(
            count(mine(None, recent)).await,
            2,
            "I148/3: count_traces and list_trace_summaries disagree about the same filter"
        );

        // 4 — a window after the batch holds nothing; the window is a real
        // bound, not a presence test.
        let later = win(after, after + chrono::Duration::hours(1));
        assert!(
            list(mine(None, later)).await.is_empty(),
            "I148/4: nothing admitted later"
        );
        assert_eq!(
            count(mine(None, later)).await,
            0,
            "I148/4: nothing counted later"
        );
    }
}

#[cfg(test)]
mod run {
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i148_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i148_admission_is_per_trace_and_filterable(&b, &suffix()).await
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i148_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i148_admission_is_per_trace_and_filterable(&b, &suffix()).await
    }
}
