//! v62.0.0 (SL-fix3b; CC 4.4.3.12, CC 2.4.1.1) — **a countersigned act's
//! stored actor is the deciding seat, whatever the arrival order.** sqlite
//! and postgres, through the statement door.
//!
//! In a one-seat affiliation a quarantine marker, a slashing verdict and a
//! takedown notice are COUNTED rows: the seat's voice and a designated
//! official's over one payload. The typed row is written once, when it
//! concludes, projected from `edition2::voices::primary_voice`, which now
//! names the deciding seat's voice (`floor_actor`): the takedown's signed
//! `claimant`, or the voice that holds `slash` (the seat's own first). So
//! when the official's voice arrives FIRST, nothing is stored naming it (a
//! held row has no typed row), and the row that lands names the seat.
//!
//! What reads that column: withdraws Rule 1 (`admission.rs`, issuer ==
//! `attesting_key_id`), quarantine's per-holder fold and `decided_by`
//! (`quarantine::fold_quarantine`, served by `resolve_quarantine_json`).
//!
//! - **I4150** — slashing, official first then seat: the row lands naming
//!   the seat; before the seat's voice there is no typed row.
//! - **I4151** — the seat withdraws its own verdict ALONE (CC 4.4.3.12 as
//!   ruled 11-21: "it takes two voices to hold power over a member and one to
//!   lay it down"). The official withdrawing its countersign alone is
//!   `countersign_withdrawal_invariants` (I4180–I4183).
//! - **I4152** — quarantine, official first then seat: lands naming the seat,
//!   and `resolve_quarantine`'s `decided_by` is the seat; before the seat's
//!   voice the fold names no one (`Clear`, `decided_by: None`).
//! - **I4153** — takedown, official first then seat: lands naming the
//!   claimant (the seat).
//! - **I4154** (CW-fix1 merge) — a slash holder of ANOTHER room (appointed by
//!   an edge naming that room) is not the deciding seat and its voice does not
//!   count: with the official's voice it is held; the seat's voice concludes
//!   it, naming the seat.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::affiliation_floor_invariants::bodies::{affiliation, seat};
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::edition2::names::RowId;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_room_with_blob, id_of, reg,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, cohort_scope, Attestation};
    use crate::federation::FederationDirectory;
    use chrono::{DateTime, Duration, Utc};

    fn base(
        by: &str,
        subject: &str,
        envelope: &serde_json::Value,
        subjects: Vec<String>,
        at: DateTime<Utc>,
    ) -> Attestation {
        let mut r = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), by, subject, envelope);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = cohort_scope::FEDERATION.into();
        r.subject_key_ids = subjects;
        r.asserted_at = at;
        r
    }

    /// Put the official's voice first, then the seat's; return the landed
    /// row.
    async fn official_first(
        d: &dyn FederationDirectory,
        st: &[u8],
        official: &str,
        what: &str,
    ) -> Attestation {
        let rid = RowId::of_statement(st).expect("a row statement");
        let out = e2::put_statement(d, &e2::voice_of(st, official))
            .await
            .unwrap_or_else(|e| panic!("{what}: the official's voice is kept: {e}"));
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "{what}: the official's voice alone is held: {out:?}"
        );
        assert!(
            d.get_attestation(&rid.hex()).await.unwrap().is_none(),
            "{what}: nothing is stored naming anyone while it is held"
        );
        let out = e2::put_statement(d, st)
            .await
            .unwrap_or_else(|e| panic!("{what}: the seat's voice: {e}"));
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "{what}: the seat's voice lands it: {out:?}"
        );
        d.get_attestation(&rid.hex())
            .await
            .unwrap()
            .expect("the landed row")
    }

    /// `by`'s `withdraws` of `target`, put through the statement door.
    async fn withdraw(
        d: &dyn FederationDirectory,
        by: &str,
        target: &Attestation,
    ) -> Result<StatementOutcome, crate::federation::Error> {
        let env = serde_json::json!({ "references_attestation_id": target.attestation_id });
        let mut w = ts::bare_attestation("", by, by, &env);
        w.attestation_type = attestation_type::WITHDRAWS.to_owned();
        w.weight = None;
        w.cohort_scope = cohort_scope::FEDERATION.into();
        let st = e2::statement_of_family(&w, by, &e2::family_of(target));
        e2::put_statement(d, &st).await
    }

    pub(crate) async fn i4150_the_seat_is_the_actor(d: &dyn FederationDirectory, s: &str) {
        let k = |n: &str| format!("i4150-{n}-{s}");
        let (f, official, m, q, solo) = (k("f"), k("official"), k("m"), k("q"), k("solo"));
        reg(d, &[&f, &official, &m, &q, &solo]).await;
        let (f, official, m, q, solo) = (
            id_of(&f),
            id_of(&official),
            id_of(&m),
            id_of(&q),
            id_of(&solo),
        );
        found_room_with_blob(
            d,
            &solo,
            "founder_only",
            &[&f],
            &[],
            Some(affiliation(Some(&official))),
        )
        .await
        .expect("I4150: a sole practitioner's affiliation");
        let at = Utc::now() - Duration::hours(3);
        seat(d, &solo, &f, &m, at).await;
        seat(d, &solo, &f, &q, at + Duration::minutes(1)).await;
        let acts = at + Duration::minutes(10);

        // ── I4150: slashing.
        let env = serde_json::json!({
            "dimension": "slashing:proven_rogue:v1",
            "score": 1.0,
            "confidence": 1.0,
            "community_id": solo,
            "payload": {},
        });
        let st = e2::counted_statement_of(&base(&f, &m, &env, vec![m.clone()], acts), &f);
        let row = official_first(d, &st, &official, "I4150").await;
        assert_eq!(row.attesting_key_id, f, "I4150: the seat is the actor");

        // ── I4151 (CC 4.4.3.12 as ruled 11-21: either voice withdraws its
        // own, alone): the seat retracts its own decision alone, under Rule 1
        // as the row's attester. (The official withdrawing its countersign
        // alone is I4180-I4183.)
        match withdraw(d, &f, &row).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("I4151: the seat withdraws its own verdict alone: {other:?}"),
        }

        // ── I4152: quarantine; `decided_by`.
        let env =
            crate::federation::quarantine::withhold_envelope(&q, &solo, "i4152-deleg", "spam");
        let st = e2::counted_statement_of(&base(&f, &q, &env, Vec::new(), acts), &f);
        let before = crate::federation::quarantine::resolve_quarantine(d, &q, Utc::now())
            .await
            .unwrap();
        let rid = RowId::of_statement(&st).expect("a row statement");
        e2::put_statement(d, &e2::voice_of(&st, &official))
            .await
            .expect("I4152: the official's voice is kept");
        let held = crate::federation::quarantine::resolve_quarantine(d, &q, Utc::now())
            .await
            .unwrap();
        assert_eq!(
            (held.state, held.decided_by.clone()),
            (before.state, before.decided_by.clone()),
            "I4152: a held marker attributes nothing"
        );
        e2::put_statement(d, &st)
            .await
            .expect("I4152: the seat's voice");
        let row = d
            .get_attestation(&rid.hex())
            .await
            .unwrap()
            .expect("I4152: landed");
        assert_eq!(row.attesting_key_id, f, "I4152: the seat is the actor");
        let fold = crate::federation::quarantine::resolve_quarantine(d, &q, Utc::now())
            .await
            .unwrap();
        assert_eq!(
            fold.decided_by.as_deref(),
            Some(f.as_str()),
            "I4152: decided_by names the seat: {fold:?}"
        );

        // ── I4153: takedown: the claimant.
        let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            format!("i4153-{s}").as_bytes(),
        ));
        let bind_env = serde_json::json!({
            "dimension": "chat:message:v1",
            "score": 1.0,
            "evidence_refs": [sha],
            "community_id": solo,
            "community_key_id": solo,
            "content_type": "text/plain",
        });
        let mut bind = base(
            &m,
            &m,
            &bind_env,
            vec![m.clone()],
            acts - Duration::minutes(1),
        );
        bind.cohort_scope = cohort_scope::AFFILIATIONS.into();
        e2::put_signed(d, &e2::row_of(&bind, &m))
            .await
            .expect("I4153: the member's content row");
        let mut digest = [0u8; 32];
        hex::decode_to_slice(&sha, &mut digest).unwrap();
        let payload = crate::federation::edition2::typed::takedown_payload(
            "community_standards",
            &f,
            &digest,
            &[],
            &crate::federation::edition2::typed::NoticeText {
                claim_text: "claim".to_owned(),
                good_faith_statement: "good faith".to_owned(),
                jurisdiction: "US".to_owned(),
            },
            e2::ms(acts + Duration::days(30)),
            e2::ms(acts),
        )
        .unwrap();
        let ciris_verify_core::cde::Value::Map(mut members) = payload else {
            panic!("a map");
        };
        members.retain(|(k, _)| k.as_text() != Some("author"));
        let st = crate::federation::edition2::typed_fixtures::typed_statement(
            &f,
            None,
            &f,
            crate::federation::edition2::typed::TAKEDOWN_PREFIX,
            &ciris_verify_core::cde::Value::Map(members),
        );
        let row = official_first(d, &st, &official, "I4153").await;
        assert_eq!(row.attesting_key_id, f, "I4153: the claimant is the actor");

        // ── I4154 (CW-fix1 merge; CC 4.5.5, CC 4.4.3.12) — a slash holder of
        // ANOTHER room is neither the deciding seat here nor a voice that
        // counts: `f` founds a second room `other` and appoints `h` to
        // `slash` there (an edge NAMING `other`). In `solo`, `h`'s voice with
        // the official's is held (no voice holds `slash` in `solo`), and when
        // the seat's voice arrives the row names the seat, not `h`.
        let (h, other) = (id_of(&k("h")), id_of(&k("other")));
        reg(d, &[&k("h"), &k("other")]).await;
        found_room_with_blob(d, &other, "majority", &[&f], &[], None)
            .await
            .expect("I4154: the other room");
        appoint_in(d, &f, &h, &other, acts - Duration::minutes(30)).await;
        let env = serde_json::json!({
            "dimension": "slashing:proven_rogue:v1",
            "score": 1.0,
            "confidence": 1.0,
            "community_id": solo,
            "payload": {},
        });
        let st = e2::counted_statement_of(
            &base(&h, &m, &env, vec![m.clone()], acts + Duration::minutes(20)),
            &h,
        );
        let rid = RowId::of_statement(&st).expect("a row statement");
        for v in [st.clone(), e2::voice_of(&st, &official)] {
            let out = e2::put_statement(d, &v)
                .await
                .expect("I4154: a voice is kept");
            assert!(
                matches!(out, StatementOutcome::Pending { .. }),
                "I4154: another room's slash holder decides nothing here: {out:?}"
            );
        }
        let why = crate::federation::edition2::fold::why_held(d, &rid)
            .await
            .unwrap()
            .expect("I4154: held");
        assert_eq!(
            why.reason,
            crate::federation::edition2::fold::reason::gc1::DELEGATED_SCOPE_UNAUTHORIZED,
            "I4154: {why:?}"
        );
        let out = e2::put_statement(d, &e2::voice_of(&st, &f))
            .await
            .expect("I4154: the seat's voice");
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "I4154: the seat's voice concludes it: {out:?}"
        );
        let row = d
            .get_attestation(&rid.hex())
            .await
            .unwrap()
            .expect("landed");
        assert_eq!(
            row.attesting_key_id, f,
            "I4154: the row names this room's seat, never another room's holder"
        );
    }

    /// `granter`'s `delegates_to(granter → grantee)` bearing `slash`, NAMING
    /// `community` (`community_id`, CW-fix1: it confers in that room only),
    /// asserted at `at`, landed with the grantee's voice.
    async fn appoint_in(
        d: &dyn FederationDirectory,
        granter: &str,
        grantee: &str,
        community: &str,
        at: DateTime<Utc>,
    ) {
        let mut envelope = serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "scope": [crate::federation::admission::DELEGATION_SCOPE_SLASH],
            "community_id": community,
        });
        crate::federation::admission::with_test_term(&mut envelope, at);
        let mut row = ts::bare_attestation("", granter, grantee, &envelope);
        row.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        row.asserted_at = at;
        ts::seal_row_in_place(granter, &mut row);
        let (out, _) = e2::land_delegation(d, &row)
            .await
            .unwrap_or_else(|e| panic!("the slash appointment in {community}: {e}"));
        assert!(
            !matches!(out, StatementOutcome::Pending { .. }),
            "the slash appointment lands: {out:?}"
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
    async fn i4150_the_seat_is_the_actor_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        crate::federation::hard_case::test_support::declare_node(&b, "ca-node").await;
        Box::pin(super::bodies::i4150_the_seat_is_the_actor(&b, &suffix())).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i4150_the_seat_is_the_actor_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        crate::federation::hard_case::test_support::declare_node(&b, "ca-node").await;
        Box::pin(super::bodies::i4150_the_seat_is_the_actor(&b, &suffix())).await;
        eprintln!("i4150 postgres: RAN");
    }
}
