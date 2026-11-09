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

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::hard_case::test_support::{declare_node, DeclaresNode};
    use crate::federation::hard_case::{self, HardCaseEvent};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type};
    use crate::federation::{FederationDirectory, SignedAttestation};

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

    /// **I1605 / I1606.**
    pub(crate) async fn i1605_i1606_a_foreign_occupant_never_blocks_the_record<B>(b: &B, s: &str)
    where
        B: FederationDirectory + DeclaresNode,
    {
        let node = format!("i1605-node-{s}");
        let peer = format!("i1605-peer-{s}");
        declare_node(b, &node).await;
        ts::register_hybrid_key_as(b, &peer, &peer, identity_type::NODE).await;

        // I1605 — the peer's row, about itself, under the v1 id this node's
        // record of `claimed` derives.
        let claimed = event(&format!("i1605-claimed-{s}"));
        let v1 = hard_case::hard_case_attestation_id(&claimed.event_id);
        let bound = hard_case::hard_case_attestation_id_for_emitter(&node, &claimed.event_id);
        assert_ne!(v1, bound, "I1605: the two derivations differ");
        let env = hard_case::hard_case_envelope(&claimed).expect("envelope");
        let mut r = ts::bare_attestation(&v1, &peer, &peer, &env);
        r.attestation_type = attestation_type::SCORES.to_owned();
        r.weight = None;
        ts::seal_row_in_place(&peer, &mut r);
        b.put_attestation(SignedAttestation { attestation: r })
            .await
            .expect("I1605: the peer's row about itself is admitted");
        let peer_row = b.get_attestation(&v1).await.unwrap().expect("held");

        let before = hard_case::foreign_occupant_fallbacks_total();
        b.record_hard_case(claimed.clone())
            .await
            .expect("I1605: a foreign occupant never blocks this node's record");
        assert!(
            hard_case::foreign_occupant_fallbacks_total() > before,
            "I1605: the fallback is counted"
        );
        let mine = b
            .get_attestation(&bound)
            .await
            .unwrap()
            .expect("I1605: this node's record is held under the emitter-bound id");
        assert_eq!(mine.attesting_key_id, node, "I1605: signed by this node");
        assert_eq!(
            hard_case::project_hard_case_row(&mine).map(|e| e.event_id),
            Some(claimed.event_id.clone()),
            "I1605: the fallback row carries this node's body and projects"
        );
        assert_eq!(
            hard_case::held_record_of(b, &node, &claimed.event_id)
                .await
                .unwrap()
                .map(|r| r.attestation_id),
            Some(bound.clone()),
            "I1605: the symmetric lookup finds it"
        );
        let listed = b
            .list_hard_case_events(hard_case::HardCaseFilter::default())
            .await
            .expect("list")
            .into_iter()
            .filter(|e| e.event_id == claimed.event_id)
            .collect::<Vec<_>>();
        assert_eq!(listed.len(), 1, "I1605: one listed event per event_id");
        assert_eq!(
            listed[0].emitter_key_id, node,
            "I1605: the listing holds this node's emitter-bound record over the v1 row"
        );
        assert_eq!(
            b.get_attestation(&v1).await.unwrap(),
            Some(peer_row),
            "I1605: the peer's row is unchanged"
        );
        b.record_hard_case(claimed.clone())
            .await
            .expect("I1605: a re-record over the foreign occupant");
        assert_eq!(
            hard_case::held_record_of(b, &node, &claimed.event_id)
                .await
                .unwrap()
                .map(|r| r.attestation_id),
            Some(bound),
            "I1605: still the one fallback record"
        );

        // I1606 — this node's own event, recorded twice: one row, at v1.
        let own = event(&format!("i1606-mine-{s}"));
        b.record_hard_case(own.clone())
            .await
            .expect("I1606: the first record");
        b.record_hard_case(own.clone())
            .await
            .expect("I1606: a re-record of this node's own event is a no-op");
        assert_eq!(
            hard_case::held_record_of(b, &node, &own.event_id)
                .await
                .unwrap()
                .map(|r| r.attestation_id),
            Some(hard_case::hard_case_attestation_id(&own.event_id)),
            "I1606: the record is at the v1 id"
        );
        assert!(
            b.get_attestation(&hard_case::hard_case_attestation_id_for_emitter(
                &node,
                &own.event_id
            ))
            .await
            .unwrap()
            .is_none(),
            "I1606: no fallback row without a foreign occupant"
        );
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
    async fn i1605_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(bodies::i1605_i1606_a_foreign_occupant_never_blocks_the_record(&b, &tag("s")))
            .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1605_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("i1605 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(bodies::i1605_i1606_a_foreign_occupant_never_blocks_the_record(&b, &tag("p")))
            .await;
        eprintln!("i1605 postgres: RAN");
    }
}
