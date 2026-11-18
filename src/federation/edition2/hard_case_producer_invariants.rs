//! v62.0.0 (v62 P3, JSON-cut slice B) — **I3055–I3056: the hard_case
//! producer states an edition-2 statement a SECOND node admits.** sqlite and
//! postgres.
//!
//! - **I3055** — node A records a `hard_case:lineage_equivocation` event
//!   (`Engine::record_hard_case`, through `edition2::produce::sign_row`). The
//!   statement is `scores` in family `hard_case:.kind`, signed by A's own key,
//!   about A. A serves it (`edition2_statements_since`), and node B admits it
//!   through the statement door (`put_edition2_statement`) under the same row
//!   id, attested by A. B's `hard_case_events` lists the event with A as its
//!   emitter: this leg needs P3.patch's edition-2 projection fence.
//! - **I3056** — re-recording the same event on A is the same statement and
//!   the same row id, with nothing new admitted (idempotence). A
//!   non-attributed `admin_action` is refused before anything is signed.
//!
//! - **I3058** — restate at the crossing: `enter_mesh` on a local hard_case
//!   row (the in-transaction door's) states its event at `federation`; the
//!   local row stays local; B admits and projects it.
//!
//! - **I3059** — an event older than the signing key's current record is
//!   asserted at the record's start and admitted; `emitted_at` keeps the
//!   original instant; a re-record is the same row.
//!
//! Mutation: stamp `asserted_at` from the clock in `hard_case_emit_input`,
//! and I3056 reds on the second row id.

pub(crate) mod bodies {
    use super::super::producer_invariants::bodies::{deliver, node};
    use crate::federation::edition2::emit::{carried_statement, family_of_statement};
    use crate::federation::edition2::ingest::{kid_of_identity_ref, statement_kid};
    use crate::federation::hard_case::{self, HardCaseEvent, HardCaseFilter};
    use crate::federation::types::identity_type;

    fn event(event_id: &str) -> HardCaseEvent {
        HardCaseEvent {
            event_id: event_id.to_owned(),
            kind: hard_case::kind::LINEAGE_EQUIVOCATION.to_owned(),
            target_key_id: None,
            subject_key_id: None,
            detail: serde_json::json!({"heads": 2}),
            emitted_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
                chrono::Utc::now().timestamp_millis(),
            )
            .expect("ms"),
            emitter_key_id: String::new(),
        }
    }

    /// I3055 / I3056.
    pub(crate) async fn i3055_a_hard_case_reaches_a_second_node(
        a_dsn: &str,
        b_dsn: &str,
        tag: &str,
    ) {
        let a = node(a_dsn, &format!("{tag}-3055-a")).await;
        let b = node(b_dsn, &format!("{tag}-3055-b")).await;
        let a_id = a
            .register_self_federation_key(identity_type::NODE, None, None)
            .await
            .expect("I3055: A registers");
        // B holds A's key record before A's rows reach it.
        let mut cursor = None;
        deliver(&a, &b, &mut cursor).await;

        let ev = event(&format!("{tag}-3055-ev"));
        let rid = a
            .record_hard_case(ev.clone())
            .await
            .expect("I3055: A records the hard_case");
        let row = a
            .federation_directory()
            .get_attestation(&rid)
            .await
            .unwrap()
            .expect("I3055: A holds its row");
        let st = carried_statement(&row).expect("I3055: the row carries its statement");
        assert_eq!(
            family_of_statement(&st),
            Some(("hard_case:.kind".to_owned(), "scores".to_owned())),
            "I3055: the family the dimension resolves to"
        );
        assert_eq!(
            statement_kid(&st),
            kid_of_identity_ref(&a_id),
            "I3055: signed by A's own key"
        );
        assert_eq!(row.attested_key_id, a_id, "I3055: about A");

        // I3056 — a re-record is the same statement, the same row.
        let again = a
            .record_hard_case(ev.clone())
            .await
            .expect("I3056: a re-record is admitted");
        assert_eq!(again, rid, "I3056: a re-record names the same row");

        // Delivered through the planes to B.
        let delivered = deliver(&a, &b, &mut cursor).await;
        assert!(delivered.contains(&st), "I3055: A serves the statement");
        assert_eq!(
            delivered.iter().filter(|s| **s == st).count(),
            1,
            "I3056: one statement for one observation"
        );
        let at_b = b
            .federation_directory()
            .get_attestation(&rid)
            .await
            .unwrap()
            .expect("I3055: B admits the row under the same row id");
        assert_eq!(at_b.attesting_key_id, a_id, "I3055: attested by A");
        let listed: Vec<HardCaseEvent> = b
            .federation_directory()
            .list_hard_case_events(HardCaseFilter {
                kind: Some(hard_case::kind::LINEAGE_EQUIVOCATION.to_owned()),
                ..HardCaseFilter::default()
            })
            .await
            .expect("list")
            .into_iter()
            .filter(|e| e.event_id == ev.event_id)
            .collect();
        assert_eq!(listed.len(), 1, "I3055: B projects the event: {listed:?}");
        assert_eq!(listed[0].emitter_key_id, a_id, "I3055: A is the emitter");

        // I3056 — an unattributed admin action signs nothing.
        let mut unattributed = event(&format!("{tag}-3056-admin"));
        unattributed.kind = hard_case::kind::ADMIN_ACTION.to_owned();
        unattributed.detail = serde_json::json!({});
        assert!(
            a.record_hard_case(unattributed).await.is_err(),
            "I3056: the attribution gate refuses before signing"
        );
        assert!(
            deliver(&a, &b, &mut cursor).await.is_empty(),
            "I3056: nothing was stated"
        );
    }

    /// **I3058** — "restate at the crossing": A records an event through
    /// the backend's in-transaction door (a local, unsigned row under its
    /// derived id), then `enter_mesh` on that row restates the event as an
    /// edition-2 statement at `federation`. `Crossed` names the STATED row
    /// (not the local id); the local row stays local; B admits the statement
    /// under the same row id and projects one event. A second crossing is the
    /// same statement (idempotent).
    pub(crate) async fn i3058_the_crossing_restates_a_local_hard_case(
        a_dsn: &str,
        b_dsn: &str,
        tag: &str,
    ) {
        use crate::federation::crossing::{self, Audience, CrossingBasis};
        use crate::federation::types::{attestation_tier, cohort_scope};
        use crate::federation::MeshCrossingOutcome;

        let a = node(a_dsn, &format!("{tag}-3058-a")).await;
        let b = node(b_dsn, &format!("{tag}-3058-b")).await;
        let a_id = a
            .register_self_federation_key(identity_type::NODE, None, None)
            .await
            .expect("I3058: A registers");
        let mut cursor = None;
        deliver(&a, &b, &mut cursor).await;

        let ev = event(&format!("{tag}-3058-ev"));
        a.federation_directory()
            .record_hard_case(ev.clone())
            .await
            .expect("I3058: the in-transaction door records");
        let local_id = hard_case::hard_case_attestation_id(&ev.event_id);
        let local = a
            .federation_directory()
            .get_attestation(&local_id)
            .await
            .unwrap()
            .expect("I3058: the local row is held");
        assert_eq!(local.tier, attestation_tier::LOCAL, "I3058: a local row");
        let ci = crossing::describe(
            &local,
            Audience::of_row(&local).expect("audience"),
            CrossingBasis::ProducerAuthority,
        )
        .expect("I3058: describable");

        let crossed = match a.enter_mesh(&local_id, &ci, None).await {
            Ok(MeshCrossingOutcome::Crossed(c)) => c,
            other => panic!("I3058: the crossing restates: {other:?}"),
        };
        assert_ne!(
            crossed.attestation_id, local_id,
            "I3058: Crossed names the stated row"
        );
        assert_eq!(
            crossed.audience,
            Audience::Federation,
            "I3058: stated at federation"
        );
        let stated = a
            .federation_directory()
            .get_attestation(&crossed.attestation_id)
            .await
            .unwrap()
            .expect("I3058: A holds the stated row");
        assert_eq!(stated.cohort_scope, cohort_scope::FEDERATION, "I3058");
        assert!(
            carried_statement(&stated).is_some(),
            "I3058: the stated row is an edition-2 statement"
        );
        assert_eq!(
            a.federation_directory()
                .get_attestation(&local_id)
                .await
                .unwrap()
                .expect("I3058: the local row stays")
                .tier,
            attestation_tier::LOCAL,
            "I3058: the local row is not signed in the earlier form"
        );

        // A second crossing is the same statement.
        match a.enter_mesh(&local_id, &ci, None).await {
            Ok(MeshCrossingOutcome::Crossed(c)) => assert_eq!(
                c.attestation_id, crossed.attestation_id,
                "I3058: a re-crossing is the same row"
            ),
            other => panic!("I3058: a re-crossing restates idempotently: {other:?}"),
        }

        deliver(&a, &b, &mut cursor).await;
        let at_b = b
            .federation_directory()
            .get_attestation(&crossed.attestation_id)
            .await
            .unwrap()
            .expect("I3058: B admits the stated row");
        assert_eq!(at_b.attesting_key_id, a_id, "I3058: attested by A");
        let listed: Vec<HardCaseEvent> = b
            .federation_directory()
            .list_hard_case_events(HardCaseFilter {
                kind: Some(hard_case::kind::LINEAGE_EQUIVOCATION.to_owned()),
                ..HardCaseFilter::default()
            })
            .await
            .expect("list")
            .into_iter()
            .filter(|e| e.event_id == ev.event_id)
            .collect();
        assert_eq!(listed.len(), 1, "I3058: B projects one event: {listed:?}");
    }

    /// **I3059** — an event observed before the signing key's current record
    /// is asserted at the record's start (`statement_instant`), so it is
    /// covered and admitted; the body keeps the event's own `emitted_at`; a
    /// re-record is the same row (deterministic per signing key).
    pub(crate) async fn i3059_an_event_older_than_the_key_is_covered(dsn: &str, tag: &str) {
        let a = node(dsn, &format!("{tag}-3059-a")).await;
        a.register_self_federation_key(identity_type::NODE, None, None)
            .await
            .expect("I3059: A registers");
        let mut ev = event(&format!("{tag}-3059-ev"));
        ev.emitted_at -= chrono::Duration::days(1);
        let rid = a
            .record_hard_case(ev.clone())
            .await
            .expect("I3059: an event older than the key is stated");
        let row = a
            .federation_directory()
            .get_attestation(&rid)
            .await
            .unwrap()
            .expect("I3059: held");
        assert!(
            row.asserted_at > ev.emitted_at && row.asserted_at <= chrono::Utc::now(),
            "I3059: asserted at the key record's start, not the event's instant"
        );
        let body_at: chrono::DateTime<chrono::Utc> = serde_json::from_value(
            row.attestation_envelope[hard_case::BODY_MEMBER]["emitted_at"].clone(),
        )
        .expect("I3059: the body carries emitted_at");
        assert_eq!(
            body_at, ev.emitted_at,
            "I3059: the original instant rides in the body"
        );
        assert_eq!(
            a.record_hard_case(ev).await.expect("I3059: re-record"),
            rid,
            "I3059: deterministic per signing key"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::bodies as b;

    fn tag() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3055_sqlite() {
        let d = tempfile::tempdir().unwrap();
        let dsn = |name: &str| {
            format!(
                "sqlite:///{}",
                d.path().join(format!("{name}.db")).display()
            )
        };
        Box::pin(b::i3055_a_hard_case_reaches_a_second_node(
            &dsn("a"),
            &dsn("b"),
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3058_sqlite() {
        let d = tempfile::tempdir().unwrap();
        let dsn = |name: &str| {
            format!(
                "sqlite:///{}",
                d.path().join(format!("{name}.db")).display()
            )
        };
        Box::pin(b::i3058_the_crossing_restates_a_local_hard_case(
            &dsn("a"),
            &dsn("b"),
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3059_sqlite() {
        let d = tempfile::tempdir().unwrap();
        let dsn = format!("sqlite:///{}", d.path().join("a.db").display());
        Box::pin(b::i3059_an_event_older_than_the_key_is_covered(
            &dsn,
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3059_postgres() {
        let Some(a) = crate::test_pg::isolated_dsn() else {
            eprintln!("i3059 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        Box::pin(b::i3059_an_event_older_than_the_key_is_covered(&a, &tag())).await;
        eprintln!("i3059 postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3058_postgres() {
        let (Some(a), Some(bb)) = (
            crate::test_pg::isolated_dsn(),
            crate::test_pg::isolated_dsn(),
        ) else {
            eprintln!("i3058 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        Box::pin(b::i3058_the_crossing_restates_a_local_hard_case(
            &a,
            &bb,
            &tag(),
        ))
        .await;
        eprintln!("i3058 postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3055_postgres() {
        let (Some(a), Some(bb)) = (
            crate::test_pg::isolated_dsn(),
            crate::test_pg::isolated_dsn(),
        ) else {
            eprintln!("i3055 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        Box::pin(b::i3055_a_hard_case_reaches_a_second_node(&a, &bb, &tag())).await;
        eprintln!("i3055 postgres: RAN");
    }
}

#[cfg(test)]
mod unit {
    use crate::federation::edition2::emit::payload_from_envelope;
    use crate::federation::hard_case::{self, HardCaseEvent};
    use ciris_verify_core::cde::Value;

    /// `4([exp, mantissa])`: a CBOR decimal fraction.
    fn decimal(exp: i64, mantissa: i64) -> Value {
        let int = |n: i64| {
            if n >= 0 {
                Value::Uint(n.unsigned_abs())
            } else {
                Value::Nint(n.unsigned_abs() - 1)
            }
        };
        Value::Tag(4, Box::new(Value::Array(vec![int(exp), int(mantissa)])))
    }

    /// **I3057** (CC ruling on reals in free-form bodies) — a hard_case
    /// body's reals reach the payload encoder unchanged (the producer never
    /// scales or restates them), and the ENCODED payload states each one
    /// exactly: an integral value as a plain integer (`2.0` -> `2`), a
    /// non-integral one as a tag-4 decimal fraction (`0.5` -> `4([-1, 5])`),
    /// at any depth. Integers are unchanged. The encoder is P1's
    /// (`payload_from_envelope(envelope, family, ..)` states every number in
    /// the `hard_case` body member, registered in `payloads::BODY_MEMBERS`,
    /// through `payloads::body_number`).
    #[test]
    fn i3057_body_reals_encode_as_int_or_decimal_fraction() {
        let detail = serde_json::json!({
            "ratio": 0.5,
            "whole": 2.0,
            "count": 3,
            "nested": {"drift": [0.5, -1.5]},
        });
        let event = HardCaseEvent {
            event_id: "i3057-ev".to_owned(),
            kind: hard_case::kind::LINEAGE_EQUIVOCATION.to_owned(),
            target_key_id: None,
            subject_key_id: None,
            detail: detail.clone(),
            emitted_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(1_790_000_000_000)
                .expect("ms"),
            emitter_key_id: String::new(),
        };
        let input = hard_case::hard_case_emit_input(&event, event.emitted_at)
            .expect("I3057: the input builds");
        let envelope = input.attestation_envelope.to_value();
        assert_eq!(
            envelope[hard_case::BODY_MEMBER]["detail"],
            detail,
            "I3057: the producer passes the body's numbers through unchanged"
        );
        let payload = payload_from_envelope(&envelope, "hard_case:.kind", 0, None, &[])
            .expect("I3057: a body with reals encodes");
        let encoded = payload
            .get_text(hard_case::BODY_MEMBER)
            .and_then(|b| b.get_text("detail"))
            .expect("I3057: the encoded detail");
        assert_eq!(
            encoded.get_text("ratio"),
            Some(&decimal(-1, 5)),
            "I3057: 0.5 -> 4([-1, 5])"
        );
        assert_eq!(
            encoded.get_text("whole"),
            Some(&Value::Uint(2)),
            "I3057: 2.0 -> 2"
        );
        assert_eq!(
            encoded.get_text("count"),
            Some(&Value::Uint(3)),
            "I3057: an integer is unchanged"
        );
        assert_eq!(
            encoded.get_text("nested").and_then(|n| n.get_text("drift")),
            Some(&Value::Array(vec![decimal(-1, 5), decimal(-1, -15)])),
            "I3057: at any depth; -1.5 -> 4([-1, -15])"
        );
    }
}
