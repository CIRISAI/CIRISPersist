//! v61.1.0 (61.1 review H3(b), as ruled) — **I1605–I1606: a foreign row at
//! a hard_case id never blocks this node's act, and never swallows its
//! record.** sqlite and postgres.
//!
//! A hard_case row's id is derived from its event's `event_id`
//! ([`hard_case_attestation_id`](crate::federation::hard_case::hard_case_attestation_id)),
//! and the writer inserts it if absent. Two nodes observing one membership
//! removal derive the same `event_id`, and a peer can pre-claim one, so the
//! id can be held by a row another key signed; the writer then returned
//! `Ok(())` having written nothing. Now this node's record is written under
//! its emitter-bound id
//! ([`hard_case_attestation_id_for_emitter`](crate::federation::hard_case::hard_case_attestation_id_for_emitter)),
//! logged and counted with `hard_case_id_held_by_foreign_row`, and the act
//! commits. The foreign row is left where it is.
//!
//! - **I1605** — a peer's row holding the v1 id of this node's event:
//!   `record_hard_case` returns `Ok`; this node's row exists under the
//!   emitter-bound id with this node's body and signer; the symmetric lookup
//!   ([`held_record_of`](crate::federation::hard_case::held_record_of)) finds
//!   it; `hard_case_events` lists this node's record for the event; the
//!   fallback counter moved; the peer's row is unchanged. A re-record writes
//!   nothing more.
//! - **I1606** — this node re-recording its own event (no foreign row) is a
//!   no-op, as before: the one row is at the v1 id, and no fallback row exists.
//!
//! Mutation: make the writer return `Ok(())` at `HeldOccupant::WriteFallback`
//! (the pre-H3 behaviour) and I1605 reds on the missing record.
//!
//! v62.0.0 (JSON cut, E5) — **I1605 is deleted**: its premise is a peer's row
//! stored at an id this node chose. An edition-2 row id is computed from the
//! statement's bytes, so no peer row can hold the id another row derives.
//! **I1606 keeps its intent** (a re-record of this node's own event is a
//! no-op: one record, one listed event) without pinning the chosen v1 id.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::hard_case::test_support::{declare_node, DeclaresNode};
    use crate::federation::hard_case::{self, HardCaseEvent};
    use crate::federation::FederationDirectory;

    fn event(event_id: &str) -> HardCaseEvent {
        HardCaseEvent {
            event_id: event_id.to_owned(),
            kind: hard_case::kind::CONSENT_SLA_BREACH.to_owned(),
            target_key_id: None,
            subject_key_id: None,
            detail: serde_json::json!({}),
            emitted_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
                chrono::Utc::now().timestamp_millis(),
            )
            .expect("ms"),
            emitter_key_id: String::new(),
        }
    }

    /// **I1606.** This node re-recording its own event is a no-op: the one
    /// record stays held, and the event lists once.
    pub(crate) async fn i1606_a_re_record_of_this_nodes_own_event_is_a_no_op<B>(b: &B, s: &str)
    where
        B: FederationDirectory + DeclaresNode,
    {
        let node = format!("i1606-node-{s}");
        declare_node(b, &node).await;

        let own = event(&format!("i1606-mine-{s}"));
        b.record_hard_case(own.clone())
            .await
            .expect("I1606: the first record");
        let first = hard_case::held_record_of(b, &node, &own.event_id)
            .await
            .unwrap()
            .map(|r| r.attestation_id)
            .expect("I1606: the record is held");
        b.record_hard_case(own.clone())
            .await
            .expect("I1606: a re-record of this node's own event is a no-op");
        assert_eq!(
            hard_case::held_record_of(b, &node, &own.event_id)
                .await
                .unwrap()
                .map(|r| r.attestation_id),
            Some(first),
            "I1606: still the one record"
        );
        let listed = b
            .list_hard_case_events(hard_case::HardCaseFilter::default())
            .await
            .expect("list")
            .into_iter()
            .filter(|e| e.event_id == own.event_id)
            .count();
        assert_eq!(listed, 1, "I1606: one listed event per event_id");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1606_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(bodies::i1606_a_re_record_of_this_nodes_own_event_is_a_no_op(&b, &tag("s"))).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1606_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("i1606 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(bodies::i1606_a_re_record_of_this_nodes_own_event_is_a_no_op(&b, &tag("p"))).await;
        eprintln!("i1606 postgres: RAN");
    }
}
