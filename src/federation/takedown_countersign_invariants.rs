//! v62.0.0 (SL-fix3a; CC 4.4.3.12) — **a takedown of a member's content in an
//! affiliation with ONE deciding seat counts only countersigned by a key
//! outside that seat.** sqlite and postgres, through the statement door, in
//! both arrival orders.
//!
//! The seat count is `affiliation_config::floor_affiliation`: the HELD record
//! of a room the content's held binding places it in, counted by its deciding
//! seats (`deciding_seats`), never the notice's own `cohort_scope` and never
//! every listed member. Before v62.0.0 the door counted every member from a
//! group the notice itself named, and never asked for a countersign at all,
//! so one voice landed.
//!
//! - **I4140** — one-seat affiliation, the seat first: the founder's counted
//!   notice is kept `Pending` (`count_short`); the designated official's
//!   voice lands it.
//! - **I4141** — the countersign first: the official's voice alone is held
//!   (`count_short`: the claimant has not voiced); the seat's voice lands it.
//! - **I4142** — an AUTHORED notice in the one-seat affiliation is refused
//!   (`author_column`): the door wants the counted form.
//! - **I4143** — a two-seat affiliation: one founder's authored notice lands
//!   alone.
//! - **I4144** — a plain community: the founder's authored notice lands
//!   alone.
//! - **I4145** — a notice whose `cohort_scope` (`affiliations`) disagrees with
//!   the held room it addresses (a plain community) concludes nothing: held
//!   `federation_affiliation_cohort_mismatch`, by name.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::affiliation_floor_invariants::bodies::{affiliation, seat};
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::fold;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::edition2::names::RowId;
    use crate::federation::edition2::typed::{takedown_payload, NoticeText, TAKEDOWN_PREFIX};
    use crate::federation::edition2::typed_fixtures::typed_statement;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_room_with_blob, id_of, reg,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, cohort_scope};
    use crate::federation::FederationDirectory;
    use chrono::{DateTime, Duration, Utc};
    use ciris_verify_core::cde::{self, Value};

    fn sha_of(tag: &str) -> String {
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(tag.as_bytes()))
    }

    /// `author`'s row binding `sha` into `room` at `scope` (the room's chat
    /// message, as I1745 places content).
    async fn bind(d: &dyn FederationDirectory, author: &str, sha: &str, room: &str, scope: &str) {
        let env = serde_json::json!({
            "dimension": "chat:message:v1",
            "score": 1.0,
            "evidence_refs": [sha],
            "community_id": room,
            "community_key_id": room,
            "content_type": "text/plain",
        });
        let mut r = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), author, author, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = scope.into();
        r.subject_key_ids = vec![author.to_owned()];
        let out = e2::put_signed(d, &e2::row_of(&r, author))
            .await
            .unwrap_or_else(|e| panic!("the content row binding {sha} into {room}: {e}"));
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "the content row lands: {out:?}"
        );
    }

    /// `claimant`'s `takedown_notice:community_standards` statement over
    /// `sha` at `at`: counted (no `author`) when `counted`, carrying the
    /// further members `extra`.
    fn notice(
        claimant: &str,
        sha: &str,
        at: DateTime<Utc>,
        counted: bool,
        extra: &[(&str, Value)],
    ) -> Vec<u8> {
        let mut digest = [0u8; 32];
        hex::decode_to_slice(sha, &mut digest).expect("a 64-hex digest");
        let kid = e2::kid_or_keep(claimant);
        let text = NoticeText {
            claim_text: "claim".to_owned(),
            good_faith_statement: "good faith".to_owned(),
            jurisdiction: "US".to_owned(),
        };
        let payload = takedown_payload(
            "community_standards",
            &kid,
            &digest,
            &[],
            &text,
            e2::ms(at + Duration::days(30)),
            e2::ms(at),
        )
        .expect("the notice payload");
        let Value::Map(mut m) = payload else {
            panic!("a statement payload is a map");
        };
        if counted {
            m.retain(|(k, _)| k.as_text() != Some("author"));
        }
        for (k, v) in extra {
            m.retain(|(key, _)| key.as_text() != Some(k));
            m.push((Value::Text((*k).to_owned()), v.clone()));
        }
        m.sort_by_key(|(k, _)| cde::encode(k));
        typed_statement(claimant, None, &kid, TAKEDOWN_PREFIX, &Value::Map(m))
    }

    async fn put(d: &dyn FederationDirectory, st: &[u8], what: &str) -> StatementOutcome {
        e2::put_statement(d, st)
            .await
            .unwrap_or_else(|e| panic!("{what}: a voice is kept or lands, never refused: {e}"))
    }

    async fn held_with(d: &dyn FederationDirectory, rid: &RowId, reason: &str, what: &str) {
        assert!(
            d.get_attestation(&rid.hex()).await.unwrap().is_none(),
            "{what}: no typed row"
        );
        let why = fold::why_held(d, rid)
            .await
            .expect("read the hold")
            .unwrap_or_else(|| panic!("{what}: held"));
        assert_eq!(why.reason, reason, "{what}: {why:?}");
    }

    async fn lands(d: &dyn FederationDirectory, out: StatementOutcome, rid: &RowId, what: &str) {
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "{what}: lands: {out:?}"
        );
        assert!(
            d.get_attestation(&rid.hex()).await.unwrap().is_some(),
            "{what}: a typed row"
        );
    }

    pub(crate) async fn i4140_one_seat_takedown_needs_a_countersign(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let k = |n: &str| format!("i4140-{n}-{s}");
        let (f, g, official, m, solo, pair, plain) = (
            k("f"),
            k("g"),
            k("official"),
            k("m"),
            k("solo"),
            k("pair"),
            k("plain"),
        );
        reg(d, &[&f, &g, &official, &m, &solo, &pair, &plain]).await;
        let (f, g, official, m, solo, pair, plain) = (
            id_of(&f),
            id_of(&g),
            id_of(&official),
            id_of(&m),
            id_of(&solo),
            id_of(&pair),
            id_of(&plain),
        );
        let at = Utc::now() - Duration::hours(3);
        found_room_with_blob(
            d,
            &solo,
            "founder_only",
            &[&f],
            &[],
            Some(affiliation(Some(&official))),
        )
        .await
        .expect("I4140: a sole practitioner's affiliation");
        seat(d, &solo, &f, &m, at).await;
        found_room_with_blob(
            d,
            &pair,
            "founder_only",
            &[&f, &g],
            &[],
            Some(affiliation(None)),
        )
        .await
        .expect("I4143: a two-seat affiliation");
        seat(d, &pair, &f, &m, at + Duration::minutes(1)).await;
        found_room_with_blob(d, &plain, "majority", &[&f], &[], None)
            .await
            .expect("I4144: a plain community");
        let acts = at + Duration::minutes(30);

        // ── I4140: the seat first.
        let sha = sha_of(&format!("{s}-i4140"));
        bind(d, &m, &sha, &solo, cohort_scope::AFFILIATIONS).await;
        let st = notice(&f, &sha, acts, true, &[]);
        let rid = RowId::of_statement(&st).expect("a row statement");
        let out = put(d, &st, "I4140").await;
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "I4140: the one seat alone is kept short: {out:?}"
        );
        held_with(d, &rid, fold::reason::COUNT_SHORT, "I4140").await;
        let out = put(d, &e2::voice_of(&st, &official), "I4140").await;
        lands(d, out, &rid, "I4140: the official's voice completes it").await;

        // ── I4141: the countersign first.
        let sha = sha_of(&format!("{s}-i4141"));
        bind(d, &m, &sha, &solo, cohort_scope::AFFILIATIONS).await;
        let st = notice(&f, &sha, acts, true, &[]);
        let rid = RowId::of_statement(&st).expect("a row statement");
        let out = put(d, &e2::voice_of(&st, &official), "I4141").await;
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "I4141: the official's voice alone is held: {out:?}"
        );
        held_with(d, &rid, fold::reason::COUNT_SHORT, "I4141").await;
        let out = put(d, &st, "I4141").await;
        lands(d, out, &rid, "I4141: the seat's voice completes it").await;

        // ── I4142: an authored notice where the door wants the counted form.
        let sha = sha_of(&format!("{s}-i4142"));
        bind(d, &m, &sha, &solo, cohort_scope::AFFILIATIONS).await;
        let e = e2::put_statement(d, &notice(&f, &sha, acts, false, &[]))
            .await
            .expect_err("I4142: an authored notice in a one-seat affiliation");
        assert!(
            e.to_string().contains("author_column"),
            "I4142: the door names the form it wants: {e}"
        );

        // ── I4143: two deciding seats: one founder acts alone.
        let sha = sha_of(&format!("{s}-i4143"));
        bind(d, &m, &sha, &pair, cohort_scope::AFFILIATIONS).await;
        let st = notice(&f, &sha, acts, false, &[]);
        let rid = RowId::of_statement(&st).expect("a row statement");
        let out = put(d, &st, "I4143").await;
        lands(d, out, &rid, "I4143: a two-seat affiliation's founder").await;

        // ── I4144: a plain community: one founder acts alone.
        let sha = sha_of(&format!("{s}-i4144"));
        bind(d, &f, &sha, &plain, cohort_scope::COMMUNITY).await;
        let st = notice(&f, &sha, acts, false, &[]);
        let rid = RowId::of_statement(&st).expect("a row statement");
        let out = put(d, &st, "I4144").await;
        lands(d, out, &rid, "I4144: a plain community's founder").await;

        // ── I4145: the notice's scope disagrees with the held room.
        let sha = sha_of(&format!("{s}-i4145"));
        bind(d, &f, &sha, &plain, cohort_scope::COMMUNITY).await;
        let st = notice(
            &f,
            &sha,
            acts + Duration::minutes(1),
            false,
            &[
                (
                    "cohort_scope",
                    Value::Text(cohort_scope::AFFILIATIONS.to_owned()),
                ),
                ("community_id", Value::Text(plain.clone())),
            ],
        );
        let rid = RowId::of_statement(&st).expect("a row statement");
        let out = put(d, &st, "I4145").await;
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "I4145: concludes nothing: {out:?}"
        );
        held_with(
            d,
            &rid,
            fold::reason::AFFILIATION_COHORT_MISMATCH,
            "I4145: held by name",
        )
        .await;
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i4140_one_seat_takedown_needs_a_countersign_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        crate::federation::hard_case::test_support::declare_node(&b, "tc-node").await;
        Box::pin(super::bodies::i4140_one_seat_takedown_needs_a_countersign(
            &b,
            &suffix(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i4140_one_seat_takedown_needs_a_countersign_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        crate::federation::hard_case::test_support::declare_node(&b, "tc-node").await;
        Box::pin(super::bodies::i4140_one_seat_takedown_needs_a_countersign(
            &b,
            &suffix(),
        ))
        .await;
        eprintln!("i4140 postgres: RAN");
    }
}
