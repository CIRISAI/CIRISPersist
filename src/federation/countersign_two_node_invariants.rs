//! v62.0.0 (SL-fix3c; CC 4.4.3.12, CC 2.6.1.9) — **a one-seat affiliation's
//! act against a member, made by two hosts through the planes.** sqlite and
//! postgres; three nodes, every row delivered by the serve feed
//! (`edition2::serve::statements_served_to`, page by page, each statement
//! through the receiving node's statement door), never copied by the test.
//!
//! Node A is the seat's (founder `f`), node B the designated official's, node
//! C a third peer. The room, its config naming the official, and every key
//! live on A only; B and C learn them from A's feed (the record and roster
//! are served to the room's designated officials, `group_serve`).
//!
//! - **I4160** — reachability: B holds the affiliation's record after one
//!   delivery from A, requested as the official.
//! - **I4161** — the producer: A drafts the verdict with
//!   `emit::draft_from_envelope_in` and it is COUNTED (no `author`); A puts the
//!   seat's voice: `Pending`.
//! - **I4162** — the seat's voice reaches B by A's feed and is held there; B
//!   lists it with `held_rows_for(official, Some("affiliation_countersign"))`,
//!   drafts its voice (`voice_draft`), signs it with the official's own key
//!   and submits it (`submit_voice`): `Seated`, the row on B naming the SEAT.
//! - **I4163** — the official's voice reaches A by B's feed: the row lands
//!   on A, naming the seat.
//! - **I4165** — the official's node receives the room's record, roster and
//!   the act awaiting its countersign, and NOTHING of the room's content (a
//!   member's message placed in the room never reaches B).
//! - **I4164** — replication reordering: a second verdict, voiced the same
//!   way, reaches C by B's feed applied in REVERSE (the official's voice
//!   first): held, then landed on the seat's voice, naming the seat.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::affiliation_config::AFFILIATION_COUNTERSIGN_ROLE;
    use crate::federation::affiliation_floor_invariants::bodies::affiliation;
    use crate::federation::edition2::emit::draft_from_envelope_in;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::edition2::liveness::statement_parts;
    use crate::federation::edition2::names::RowId;
    use crate::federation::edition2::second_signer_voice::{
        held_rows_for, submit_voice, voice_draft, VoiceOutcome,
    };
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_room_with_blob, id_of, reg,
    };
    use crate::federation::FederationDirectory;
    use chrono::{DateTime, Duration, Utc};

    /// The statements `from` serves to `requester`, every page.
    async fn served<B: FederationDirectory + Sync>(from: &B, requester: &str) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut cursor = None;
        loop {
            let page = crate::federation::edition2::serve::statements_served_to(
                from,
                cursor.as_ref(),
                256,
                Some(requester),
            )
            .await
            .unwrap();
            let Some(next) = page.next else { break };
            cursor = Some(next);
            out.extend(page.statements.into_iter().map(|st| st.bytes));
        }
        out
    }

    /// Deliver `from`'s feed for `requester` to `to`, in feed order or
    /// reversed, through `to`'s statement door. A statement `to` cannot take
    /// yet (its predecessor not delivered) is left, as a peer leaves it; a
    /// slashing verdict's voice is never refused.
    async fn deliver<B: FederationDirectory + Sync>(
        from: &B,
        to: &B,
        requester: &str,
        reverse: bool,
    ) {
        let mut feed = served(from, requester).await;
        if reverse {
            feed.reverse();
        }
        let slashing = ciris_verify_core::namespace_match::family_id("slashing:{outcome}");
        for st in feed {
            let is_verdict = statement_parts(&st)
                .and_then(|(p, _)| {
                    p.get_int(-70002)
                        .and_then(|v| v.as_text().map(str::to_owned))
                })
                .is_some_and(|f| f == slashing);
            match e2::put_statement(to, &st).await {
                Ok(_) => {}
                Err(e) if is_verdict => panic!("a delivered verdict voice is refused: {e}"),
                Err(_) => {}
            }
        }
    }

    /// The seat's verdict on `accused`, drafted by A's producer and signed by
    /// the seat's own key.
    async fn seat_verdict<B: FederationDirectory + Sync>(
        a: &B,
        f: &str,
        accused: &str,
        room: &str,
        at: DateTime<Utc>,
    ) -> Vec<u8> {
        let env = serde_json::json!({
            "dimension": "slashing:proven_rogue:v1",
            "score": 1.0,
            "confidence": 1.0,
            "community_id": room,
            "subject_key_ids": [accused],
            "cohort_scope": "federation",
            "payload": {},
        });
        let draft = draft_from_envelope_in(
            a,
            &e2::kid_digest(f),
            &e2::kid_or_keep(f),
            accused,
            "scores",
            &env,
            e2::ms(at),
            None,
        )
        .await
        .expect("I4161: the seat's verdict drafts");
        let sig = e2::signing_key(f)
            .sign(&draft.sig_structure)
            .expect("the seat's own key signs");
        let st = draft.assemble(sig);
        let (_, payload) = statement_parts(&st).expect("a statement");
        assert!(
            payload.get_text("author").is_none(),
            "I4161: in a one-seat affiliation the verdict is drafted COUNTED"
        );
        st
    }

    /// B, the official's host: list the held row, draft and sign its voice,
    /// submit it.
    async fn countersign<B: FederationDirectory + Sync>(
        b: &B,
        official: &str,
        rid: &RowId,
        what: &str,
    ) {
        let held = held_rows_for(b, official, Some(AFFILIATION_COUNTERSIGN_ROLE), None, 100)
            .await
            .unwrap();
        let row = held
            .iter()
            .find(|h| h.row_id == rid.hex())
            .unwrap_or_else(|| panic!("{what}: the official lists the held verdict: {held:?}"));
        assert_eq!(row.role, AFFILIATION_COUNTERSIGN_ROLE, "{what}");
        let draft = voice_draft(&row.statement, official).expect("the official's voice drafts");
        let sig = e2::signing_key(official)
            .sign(&draft.sig_structure)
            .expect("the official's own key signs");
        match submit_voice(b, &draft.assemble(sig)).await.unwrap() {
            VoiceOutcome::Seated { row_id } => assert_eq!(row_id, rid.hex(), "{what}"),
            other => panic!("{what}: the countersign seats it: {other:?}"),
        }
    }

    async fn attester<B: FederationDirectory + Sync>(d: &B, rid: &RowId) -> Option<String> {
        d.get_attestation(&rid.hex())
            .await
            .unwrap()
            .map(|r| r.attesting_key_id)
    }

    pub(crate) async fn i4160_two_hosts_countersign_through_the_planes<B>(
        a: &B,
        b: &B,
        c: &B,
        s: &str,
    ) where
        B: FederationDirectory + Sync,
    {
        let k = |n: &str| format!("i4160-{n}-{s}");
        let (f, official, m, solo) = (k("f"), k("official"), k("m"), k("solo"));
        reg(a, &[&f, &official, &m, &solo]).await;
        let (f, official, m, solo) = (id_of(&f), id_of(&official), id_of(&m), id_of(&solo));
        found_room_with_blob(
            a,
            &solo,
            "founder_only",
            &[&f],
            &[],
            Some(affiliation(Some(&official))),
        )
        .await
        .expect("the seat's affiliation, on A");

        // The room's content: the founder's message placed in the affiliation.
        let content = {
            let env = serde_json::json!({
                "dimension": "chat:message:v1",
                "score": 1.0,
                "evidence_refs": [hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                    format!("i4165-{s}").as_bytes(),
                ))],
                "community_id": solo,
                "community_key_id": solo,
                "content_type": "text/plain",
            });
            let mut r =
                crate::federation::tier_ingest::test_support::bare_attestation("", &f, &f, &env);
            r.attestation_type = crate::federation::types::attestation_type::SCORES.into();
            r.weight = None;
            r.cohort_scope = crate::federation::types::cohort_scope::AFFILIATIONS.into();
            r.subject_key_ids = vec![f.clone()];
            let row = e2::row_of(&r, &f);
            let out = e2::put_signed(a, &row)
                .await
                .expect("the room's message, on A");
            assert!(
                matches!(out, StatementOutcome::Row { .. }),
                "the room's message lands on A: {out:?}"
            );
            row
        };

        // ── I4160: B and C learn the room from A's feed, as the official.
        deliver(a, b, &official, false).await;
        deliver(a, c, &official, false).await;
        for (n, d) in [("B", b), ("C", c)] {
            assert!(
                d.lookup_community(&solo).await.unwrap().is_some(),
                "I4160: {n} holds the affiliation's record from A's feed"
            );
        }
        // ── I4165 (CC 4.4.3.12 as ruled 11-21: "designation makes it a party
        // to that decision, not a member") — the official's node receives the
        // room's record, roster and the act awaiting its countersign, and
        // NOTHING of the room's content.
        let content_id = RowId::of_statement(
            &crate::federation::edition2::emit::carried_statement(&content)
                .expect("a carried statement"),
        )
        .expect("a row id");
        assert!(
            b.get_attestation(&content_id.hex())
                .await
                .unwrap()
                .is_none()
                && b.edition2_voices(&content_id).await.unwrap().is_empty(),
            "I4165: the official's node holds none of the room's content"
        );

        // ── I4161: A drafts and puts the seat's voice.
        let at = Utc::now() - Duration::hours(1);
        let st = seat_verdict(a, &f, &m, &solo, at).await;
        let rid = RowId::of_statement(&st).expect("a row statement");
        let out = e2::put_statement(a, &st).await.expect("I4161: A keeps it");
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "I4161: the seat's voice alone is held on A: {out:?}"
        );

        // ── I4162: to B by A's feed; B countersigns.
        deliver(a, b, &official, false).await;
        assert!(
            attester(b, &rid).await.is_none(),
            "I4162: held on B before the countersign"
        );
        countersign(b, &official, &rid, "I4162").await;
        assert_eq!(
            attester(b, &rid).await.as_deref(),
            Some(f.as_str()),
            "I4162: B's row names the seat"
        );

        // ── I4163: back to A by B's feed.
        deliver(b, a, &f, false).await;
        assert_eq!(
            attester(a, &rid).await.as_deref(),
            Some(f.as_str()),
            "I4163: A's row lands, naming the seat"
        );

        // ── I4164: the reverse arrival order, by replication reordering.
        let st2 = seat_verdict(a, &f, &m, &solo, at + Duration::minutes(5)).await;
        let rid2 = RowId::of_statement(&st2).expect("a row statement");
        e2::put_statement(a, &st2).await.expect("I4164: A keeps it");
        deliver(a, b, &official, false).await;
        countersign(b, &official, &rid2, "I4164").await;
        deliver(b, c, &official, true).await;
        assert_eq!(
            attester(c, &rid2).await.as_deref(),
            Some(f.as_str()),
            "I4164: on C the official's voice arrived first, and the row names the seat"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i4160_two_hosts_countersign_through_the_planes_sqlite() {
        use crate::store::Backend as _;
        let mut nodes = Vec::new();
        for n in ["a", "b", "c"] {
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            crate::federation::hard_case::test_support::declare_node(&b, &format!("tn-{n}")).await;
            nodes.push(b);
        }
        Box::pin(
            super::bodies::i4160_two_hosts_countersign_through_the_planes(
                &nodes[0],
                &nodes[1],
                &nodes[2],
                &suffix(),
            ),
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i4160_two_hosts_countersign_through_the_planes_postgres() {
        use crate::store::Backend as _;
        let mut nodes = Vec::new();
        for n in ["a", "b", "c"] {
            let Some(dsn) = crate::test_pg::empty_dsn() else {
                return;
            };
            let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            crate::federation::hard_case::test_support::declare_node(&b, &format!("tn-{n}")).await;
            nodes.push(b);
        }
        Box::pin(
            super::bodies::i4160_two_hosts_countersign_through_the_planes(
                &nodes[0],
                &nodes[1],
                &nodes[2],
                &suffix(),
            ),
        )
        .await;
        eprintln!("i4160 postgres: RAN");
    }
}
