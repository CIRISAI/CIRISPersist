//! v62.0.0 (v62 P3; CC 2.6.1.3, CLM-silo-projection-rebuildable) —
//! **I3050–I3054: a `hard_case:*` row carrying an edition-2 statement
//! projects into `hard_case_events`, fenced by the id its bytes compute.**
//! sqlite and postgres.
//!
//! The earlier form's projection fence asked that a hard_case row's id be
//! derived from its event (`hard_case_attestation_id`, or the signer's
//! emitter-bound id). An edition-2 row id is computed from the statement
//! (`RowId::of_statement`), so that fence refused every edition-2 row. The
//! fence for an edition-2 row (`hard_case::edition2_hard_case_event`) asks
//! the same three properties over what the row carries: the id is the
//! carried statement's, the emitter is the author that id commits to, and
//! the envelope's dimension and body are the statement payload's.
//!
//! - **I3050** — an edition-2 `hard_case:lineage_equivocation:v1` row
//!   projects; the emitter is its signer.
//! - **I3051** — the fence's bad cases: the derived (earlier-form) id on an
//!   edition-2 row, an id that is no statement's, a body or dimension that is
//!   not the statement's, a signer that is not the author, another
//!   statement carried under this row's id. The earlier-form fence still
//!   refuses an id its body does not name.
//! - **I3052** — an `emitted_at` carried as POSIX ms (CC 2.6.2) projects as
//!   that instant.
//! - **I3053** — through the door (`put_statement`): the row projects; a
//!   re-put of the same statement keeps one row and one event (idempotence);
//!   the same emitter's second statement for the same `event_id` is a second
//!   row but still one event (the table is keyed on `event_id`); another
//!   emitter's statement for that `event_id` lands under its own id and never
//!   occupies this emitter's (no pre-claim).
//! - **I3054** — a mapped edition-2 row offered under the earlier form's
//!   derived id is refused at the door and projects nothing.
//!
//! Mutation: make `edition2_hard_case_event` skip the `RowId::of_statement`
//! comparison and I3051 reds on the derived-id and foreign-statement legs;
//! restore the earlier fence for carried rows and I3050/I3053 red.

#[cfg(test)]
mod unit {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::STATEMENT_MEMBER;
    use crate::federation::hard_case::{self, HardCaseEvent};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, Attestation};

    fn now_ms() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            chrono::Utc::now().timestamp_millis(),
        )
        .expect("ms")
    }

    fn event(event_id: &str) -> HardCaseEvent {
        HardCaseEvent {
            event_id: event_id.to_owned(),
            kind: hard_case::kind::LINEAGE_EQUIVOCATION.to_owned(),
            target_key_id: None,
            subject_key_id: None,
            detail: serde_json::json!({"heads": 2}),
            emitted_at: now_ms(),
            emitter_key_id: String::new(),
        }
    }

    /// The earlier-shaped literal of `seed`'s hard_case row about itself.
    fn literal(seed: &str, envelope: &serde_json::Value) -> Attestation {
        let mut a = ts::bare_attestation("unused", seed, seed, envelope);
        a.attestation_type = attestation_type::SCORES.to_owned();
        let at = now_ms();
        a.asserted_at = at;
        a.scrub_timestamp = at;
        a
    }

    fn edition2_row(seed: &str, ev: &HardCaseEvent) -> Attestation {
        let envelope = hard_case::hard_case_envelope(ev).expect("envelope");
        e2::row_of(&literal(seed, &envelope), seed)
    }

    /// **I3050** — an edition-2 hard_case row projects; the emitter is its
    /// signer, the event is the statement's.
    #[test]
    fn i3050_an_edition2_hard_case_row_projects() {
        let ev = event("i3050-ev");
        let row = edition2_row("i3050-node", &ev);
        assert!(
            row.attestation_envelope.get(STATEMENT_MEMBER).is_some(),
            "I3050: the fixture is an edition-2 row"
        );
        assert_eq!(
            row.attestation_id,
            e2::rid(&row),
            "I3050: stored under its row id"
        );
        let projected = hard_case::project_hard_case_row(&row).expect("I3050: it projects");
        assert_eq!(projected.event_id, ev.event_id, "I3050");
        assert_eq!(projected.kind, ev.kind, "I3050");
        assert_eq!(projected.detail, ev.detail, "I3050");
        assert_eq!(projected.emitted_at, ev.emitted_at, "I3050");
        assert_eq!(
            projected.emitter_key_id,
            e2::kid("i3050-node"),
            "I3050: the emitter is the row's signer"
        );
    }

    /// **I3051** — the edition-2 fence refuses every row whose parts
    /// disagree, and the earlier-form fence still refuses its own bad case.
    #[test]
    fn i3051_the_fence_refuses_a_row_whose_parts_disagree() {
        let ev = event("i3051-ev");
        let row = edition2_row("i3051-node", &ev);
        assert!(
            hard_case::project_hard_case_row(&row).is_some(),
            "I3051: control"
        );

        // The earlier form's derived id is not an edition-2 row's id.
        let mut derived = row.clone();
        derived.attestation_id = hard_case::hard_case_attestation_id(&ev.event_id);
        assert_eq!(
            hard_case::project_hard_case_row(&derived),
            None,
            "I3051: the derived id on a carried statement"
        );
        let mut bound = row.clone();
        bound.attestation_id =
            hard_case::hard_case_attestation_id_for_emitter(&row.attesting_key_id, &ev.event_id);
        assert_eq!(
            hard_case::project_hard_case_row(&bound),
            None,
            "I3051: the emitter-bound id on a carried statement"
        );

        // An id that is no statement's.
        let mut other_id = row.clone();
        other_id.attestation_id = "00".repeat(32);
        assert_eq!(
            hard_case::project_hard_case_row(&other_id),
            None,
            "I3051: an id the statement does not compute"
        );

        // The body is not the statement's.
        let mut body = row.clone();
        body.attestation_envelope[hard_case::BODY_MEMBER]["detail"] =
            serde_json::json!({"heads": 3});
        assert_eq!(
            hard_case::project_hard_case_row(&body),
            None,
            "I3051: a body the statement does not carry"
        );

        // The dimension is not the statement's (nor the body's).
        let mut dimension = row.clone();
        dimension.attestation_envelope["dimension"] = serde_json::json!(
            hard_case::hard_case_dimension(hard_case::kind::CONSENT_SLA_BREACH)
        );
        assert_eq!(
            hard_case::project_hard_case_row(&dimension),
            None,
            "I3051: a dimension the statement does not carry"
        );

        // The signer is not the author the id commits to.
        let mut signer = row.clone();
        signer.attesting_key_id = e2::kid("i3051-other");
        assert_eq!(
            hard_case::project_hard_case_row(&signer),
            None,
            "I3051: a signer that is not the author"
        );

        // Another statement carried under this row's id.
        let other = edition2_row("i3051-node", &event("i3051-other-ev"));
        let mut swapped = row.clone();
        swapped.attestation_envelope[STATEMENT_MEMBER] =
            other.attestation_envelope[STATEMENT_MEMBER].clone();
        assert_eq!(
            hard_case::project_hard_case_row(&swapped),
            None,
            "I3051: a statement whose id is not the row's"
        );

        // The earlier-form fence is unchanged: an id the body does not name.
        {
            let envelope = hard_case::hard_case_envelope(&ev).expect("envelope");
            let earlier = |id: &str| {
                let mut r = ts::bare_attestation(id, "i3051-node", "", &envelope);
                r.attestation_type = attestation_type::SCORES.to_owned();
                r
            };
            assert!(
                hard_case::project_hard_case_row(&earlier(&hard_case::hard_case_attestation_id(
                    &ev.event_id
                )))
                .is_some(),
                "I3051: an earlier-form row under its derived id projects"
            );
            assert_eq!(
                hard_case::project_hard_case_row(&earlier("not-the-derived-id")),
                None,
                "I3051: the earlier-form fence still refuses an id its body does not name"
            );
        };
    }

    /// **I3052** — an `emitted_at` carried as POSIX ms projects as that
    /// instant.
    #[test]
    fn i3052_an_emitted_at_in_ms_projects_as_that_instant() {
        let ev = event("i3052-ev");
        let mut envelope = hard_case::hard_case_envelope(&ev).expect("envelope");
        envelope[hard_case::BODY_MEMBER]["emitted_at"] =
            serde_json::json!(ev.emitted_at.timestamp_millis());
        let row = e2::row_of(&literal("i3052-node", &envelope), "i3052-node");
        assert_eq!(
            hard_case::project_hard_case_row(&row).map(|e| e.emitted_at),
            Some(ev.emitted_at),
            "I3052: the ms instant is the event's instant"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::hard_case::{self, HardCaseEvent, HardCaseFilter};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, Attestation};
    use crate::federation::{FederationDirectory, SignedAttestation};

    fn ms(at: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(at.timestamp_millis()).expect("ms")
    }

    fn event(event_id: &str, at: chrono::DateTime<chrono::Utc>) -> HardCaseEvent {
        HardCaseEvent {
            event_id: event_id.to_owned(),
            kind: hard_case::kind::LINEAGE_EQUIVOCATION.to_owned(),
            target_key_id: None,
            subject_key_id: None,
            detail: serde_json::json!({}),
            emitted_at: at,
            emitter_key_id: String::new(),
        }
    }

    /// `seed`'s hard_case row about itself for `ev`, asserted at `at`, as an
    /// edition-2 statement.
    fn statement(seed: &str, ev: &HardCaseEvent, at: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
        let envelope = hard_case::hard_case_envelope(ev).expect("envelope");
        let mut a: Attestation = ts::bare_attestation("unused", seed, seed, &envelope);
        a.attestation_type = attestation_type::SCORES.to_owned();
        a.asserted_at = at;
        a.scrub_timestamp = at;
        e2::statement_of(&a, seed)
    }

    fn outcome(o: &StatementOutcome) -> (String, bool) {
        match o {
            StatementOutcome::KeyPlane { row_id, new }
            | StatementOutcome::Voice { row_id, new }
            | StatementOutcome::Row { row_id, new }
            | StatementOutcome::Pending { row_id, new } => (row_id.hex(), *new),
        }
    }

    async fn events_for<B>(b: &B, event_id: &str) -> Vec<HardCaseEvent>
    where
        B: FederationDirectory + ?Sized,
    {
        b.list_hard_case_events(HardCaseFilter {
            kind: Some(hard_case::kind::LINEAGE_EQUIVOCATION.to_owned()),
            ..HardCaseFilter::default()
        })
        .await
        .expect("list")
        .into_iter()
        .filter(|e| e.event_id == event_id)
        .collect()
    }

    /// **I3053** — through the door: the row projects, a re-put is
    /// idempotent, one `event_id` is one event, and another emitter never
    /// occupies this emitter's id.
    pub(crate) async fn i3053_an_edition2_hard_case_projects_through_the_door<B>(b: &B, s: &str)
    where
        B: FederationDirectory + ?Sized,
    {
        let node = format!("i3053-node-{s}");
        let peer = format!("i3053-peer-{s}");
        let node_kid = e2::put_key(b, &node, &["node"]).await;
        let peer_kid = e2::put_key(b, &peer, &["node"]).await;
        let t1 = ms(chrono::Utc::now());
        let ev = event(&format!("i3053-ev-{s}"), t1);

        let st1 = statement(&node, &ev, t1);
        let (rid1, new) = outcome(&e2::put_statement(b, &st1).await.expect("I3053: admitted"));
        assert!(new, "I3053: the first put is new");
        let listed = events_for(b, &ev.event_id).await;
        assert_eq!(listed.len(), 1, "I3053: the row projects: {listed:?}");
        assert_eq!(
            listed[0].emitter_key_id, node_kid,
            "I3053: the emitter is the signer"
        );
        assert_eq!(listed[0].kind, ev.kind, "I3053");

        // The same statement again: the same row, nothing new.
        let (again, new) = outcome(&e2::put_statement(b, &st1).await.expect("I3053: re-put"));
        assert_eq!(again, rid1, "I3053: a re-put names the same row");
        assert!(!new, "I3053: a re-put is not new");
        assert_eq!(
            events_for(b, &ev.event_id).await.len(),
            1,
            "I3053: still one event"
        );

        // The same emitter's second statement for the event: a second row,
        // still one event.
        let t2 = t1 - chrono::Duration::seconds(1);
        let st2 = statement(&node, &ev, t2);
        let (rid2, new) = outcome(&e2::put_statement(b, &st2).await.expect("I3053: second"));
        assert!(
            new && rid2 != rid1,
            "I3053: a different statement is a different row"
        );
        assert_eq!(
            events_for(b, &ev.event_id).await.len(),
            1,
            "I3053: hard_case_events keeps one event per event_id"
        );

        // Another emitter's statement for the same event_id: its own id.
        let st3 = statement(&peer, &ev, t1);
        let (rid3, new) = outcome(&e2::put_statement(b, &st3).await.expect("I3053: peer"));
        assert!(new, "I3053: the peer's record is kept");
        assert!(
            rid3 != rid1 && rid3 != rid2,
            "I3053: the author is in the id"
        );
        let mine = b
            .get_attestation(&rid1)
            .await
            .expect("get")
            .expect("I3053: this emitter's row is still held");
        assert_eq!(mine.attesting_key_id, node_kid, "I3053: never pre-claimed");
        let theirs = b
            .get_attestation(&rid3)
            .await
            .expect("get")
            .expect("I3053: the peer's row is held");
        assert_eq!(theirs.attesting_key_id, peer_kid, "I3053");
        assert_eq!(
            events_for(b, &ev.event_id).await.len(),
            1,
            "I3053: still one event for the event_id"
        );
    }

    /// **I3054** — a mapped edition-2 row offered under the earlier form's
    /// derived id is refused at the door, and nothing projects.
    pub(crate) async fn i3054_the_derived_id_is_refused_at_the_door<B>(b: &B, s: &str)
    where
        B: FederationDirectory + ?Sized,
    {
        let node = format!("i3054-node-{s}");
        e2::put_key(b, &node, &["node"]).await;
        let at = ms(chrono::Utc::now());
        let ev = event(&format!("i3054-ev-{s}"), at);
        let mut row = e2::row_of_statement(
            &statement(&node, &ev, at),
            crate::federation::edition2::ingest::INGEST_TIER,
        );
        row.attestation_id = hard_case::hard_case_attestation_id(&ev.event_id);
        assert!(
            b.put_attestation(SignedAttestation { attestation: row })
                .await
                .is_err(),
            "I3054: an edition-2 row under a derived id is refused"
        );
        assert!(
            events_for(b, &ev.event_id).await.is_empty(),
            "I3054: nothing projects"
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
    async fn sqlite() -> crate::store::sqlite::SqliteBackend {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[cfg(feature = "postgres")]
    async fn postgres(what: &str) -> Option<crate::store::postgres::PostgresBackend> {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("{what} postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return None;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i3053_sqlite() {
        let b = sqlite().await;
        Box::pin(bodies::i3053_an_edition2_hard_case_projects_through_the_door(&b, &tag("s")))
            .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i3053_postgres() {
        let Some(b) = postgres("i3053").await else {
            return;
        };
        Box::pin(bodies::i3053_an_edition2_hard_case_projects_through_the_door(&b, &tag("p")))
            .await;
        eprintln!("i3053 postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i3054_sqlite() {
        let b = sqlite().await;
        Box::pin(bodies::i3054_the_derived_id_is_refused_at_the_door(
            &b,
            &tag("s"),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i3054_postgres() {
        let Some(b) = postgres("i3054").await else {
            return;
        };
        Box::pin(bodies::i3054_the_derived_id_is_refused_at_the_door(
            &b,
            &tag("p"),
        ))
        .await;
        eprintln!("i3054 postgres: RAN");
    }
}
