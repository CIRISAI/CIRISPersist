//! v62.0.0 (SL-fix3d; CC 4.4.3.12 as ruled 11-21: "it takes two voices to
//! hold power over a member and one to lay it down") — **a designated
//! official withdraws its own countersign ALONE, and the act un-concludes
//! forward, back to waiting for a countersign.** sqlite and postgres,
//! through the statement door, in both voice orders.
//!
//! How one voice of a COUNTED row is withdrawn: the official signs an
//! authored `withdraws` naming the row (`refs.target`).
//! `affiliation_config::check_floor_act_withdrawal` admits it UNSTAMPED: it
//! retires nothing itself (the retraction folds honour only the row's
//! producer and a stamp). It is the official's voice that is withdrawn:
//! `affiliation_config::standing_voices` stops counting that official, and the
//! withdrawal touches the row it names, so the act re-folds, fails its
//! countersign, and un-concludes (its typed row leaves the table; it is held
//! `count_short`). What was done under it stands. A further designated
//! official's countersign concludes it again (the withdrawn official's own
//! voice never counts again for that row).
//!
//! The room: a sole practitioner's affiliation (one founder `f`) naming TWO
//! designated officials `o1`, `o2`.
//!
//! - **I4180** — slashing, the seat's voice first then `o1`'s: concluded;
//!   `o1` withdraws alone: the withdrawal lands, the act un-concludes (no
//!   typed row, held `count_short`), and `held_rows_for` offers it to `o2`
//!   (not to `o1`); `o2`'s voice concludes it again, naming the seat.
//! - **I4181** — the same with `o1`'s voice first.
//! - **I4182** — quarantine, seat first: after `o1`'s withdrawal the marker no
//!   longer withholds; `o2`'s countersign withholds again.
//! - **I4183** — a key that is neither the seat nor a voicing official may not
//!   withdraw it (`federation_withdraws_not_admitted` or held, never landed).

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::affiliation_config::AFFILIATION_COUNTERSIGN_ROLE;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::fold;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::edition2::names::RowId;
    use crate::federation::edition2::second_signer_voice::held_rows_for;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_room_with_blob, id_of, reg,
    };
    use crate::federation::quarantine::{resolve_quarantine, QuarantineState};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, cohort_scope, Attestation};
    use crate::federation::FederationDirectory;
    use chrono::{DateTime, Duration, Utc};

    fn two_officials(o1: &str, o2: &str) -> serde_json::Value {
        let mut b = serde_json::json!({
            crate::federation::affiliation_config::POLICY_COHORT_FIELD: "affiliations",
        });
        b[crate::federation::affiliation_config::POLICY_AFFILIATION_CONFIG_FIELD] = serde_json::json!({
            "designated_officials": [
                { "role": "privacy_officer", "key_id": o1 },
                { "role": "records_officer", "key_id": o2 },
            ],
        });
        b
    }

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

    async fn put(d: &dyn FederationDirectory, st: &[u8], what: &str) -> StatementOutcome {
        e2::put_statement(d, st)
            .await
            .unwrap_or_else(|e| panic!("{what}: kept or landed, never refused: {e}"))
    }

    /// `by`'s authored `withdraws` of `target`.
    fn withdrawal(by: &str, target: &Attestation) -> Vec<u8> {
        let env = serde_json::json!({ "references_attestation_id": target.attestation_id });
        let mut w = ts::bare_attestation("", by, by, &env);
        w.attestation_type = attestation_type::WITHDRAWS.to_owned();
        w.weight = None;
        w.cohort_scope = cohort_scope::FEDERATION.into();
        e2::statement_of_family(&w, by, &e2::family_of(target))
    }

    /// Land `st` with the seat's and `o1`'s voices in the given order;
    /// return the landed row.
    async fn conclude(
        d: &dyn FederationDirectory,
        st: &[u8],
        o1: &str,
        seat_first: bool,
        what: &str,
    ) -> Attestation {
        let rid = RowId::of_statement(st).expect("a row statement");
        let voice = e2::voice_of(st, o1);
        let (first, second) = if seat_first {
            (st.to_vec(), voice)
        } else {
            (voice, st.to_vec())
        };
        put(d, &first, what).await;
        let out = put(d, &second, what).await;
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "{what}: both voices conclude it: {out:?}"
        );
        d.get_attestation(&rid.hex())
            .await
            .unwrap()
            .expect("the concluded row")
    }

    /// `o1` withdraws its countersign; the act un-concludes and waits for a
    /// countersign that `o2`, and not `o1`, is offered.
    async fn withdraw_countersign(
        d: &dyn FederationDirectory,
        row: &Attestation,
        o1: &str,
        o2: &str,
        what: &str,
    ) {
        let rid = crate::federation::edition2::voices::carried_row_id(row).expect("a row id");
        let out = put(d, &withdrawal(o1, row), what).await;
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "{what}: the official's withdrawal of its own countersign lands alone: {out:?}"
        );
        assert!(
            d.get_attestation(&rid.hex()).await.unwrap().is_none(),
            "{what}: the act un-concludes forward"
        );
        let why = fold::why_held(d, &rid)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{what}: held again"));
        assert_eq!(
            why.reason,
            fold::reason::COUNT_SHORT,
            "{what}: back to waiting for a countersign: {why:?}"
        );
        let offered = |k: String| async move {
            held_rows_for(d, &k, Some(AFFILIATION_COUNTERSIGN_ROLE), None, 100)
                .await
                .unwrap()
                .iter()
                .any(|h| h.row_id == rid.hex())
        };
        assert!(offered(o2.to_owned()).await, "{what}: o2 is offered it");
        assert!(
            !offered(o1.to_owned()).await,
            "{what}: o1, whose voice is withdrawn, is not"
        );
    }

    pub(crate) async fn i4180_an_official_withdraws_its_countersign_alone(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let k = |n: &str| format!("i4180-{n}-{s}");
        let (f, o1, o2, m, x, q, solo) =
            (k("f"), k("o1"), k("o2"), k("m"), k("x"), k("q"), k("solo"));
        reg(d, &[&f, &o1, &o2, &m, &x, &q, &solo]).await;
        let (f, o1, o2, m, x, q, solo) = (
            id_of(&f),
            id_of(&o1),
            id_of(&o2),
            id_of(&m),
            id_of(&x),
            id_of(&q),
            id_of(&solo),
        );
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let solo = found_room_with_blob(
            d,
            &solo,
            "founder_only",
            &[&f],
            &[],
            Some(two_officials(&o1, &o2)),
        )
        .await
        .expect("I4180: a sole practitioner's affiliation with two officials");
        let at = Utc::now() - Duration::hours(2);
        let verdict = |t: DateTime<Utc>| {
            let env = serde_json::json!({
                "dimension": "slashing:proven_rogue:v1",
                "score": 1.0,
                "confidence": 1.0,
                "community_id": solo,
                "payload": {},
            });
            e2::counted_statement_of(&base(&f, &m, &env, vec![m.clone()], t), &f)
        };

        // ── I4180 / I4181: both voice orders.
        for (seat_first, what, t) in [
            (true, "I4180", at),
            (false, "I4181", at + Duration::minutes(5)),
        ] {
            let st = verdict(t);
            let row = conclude(d, &st, &o1, seat_first, what).await;
            assert_eq!(row.attesting_key_id, f, "{what}: the seat is the actor");
            withdraw_countersign(d, &row, &o1, &o2, what).await;
            let out = put(d, &e2::voice_of(&st, &o2), what).await;
            assert!(
                matches!(out, StatementOutcome::Row { .. }),
                "{what}: a further official's countersign concludes it again: {out:?}"
            );
            let again = d
                .get_attestation(&row.attestation_id)
                .await
                .unwrap()
                .expect("concluded again");
            assert_eq!(again.attesting_key_id, f, "{what}: still the seat's act");
        }

        // ── I4182: quarantine: the marker stops withholding, then resumes.
        let env =
            crate::federation::quarantine::withhold_envelope(&q, &solo, "i4182-deleg", "spam");
        let st = e2::counted_statement_of(
            &base(&f, &q, &env, Vec::new(), at + Duration::minutes(10)),
            &f,
        );
        let row = conclude(d, &st, &o1, true, "I4182").await;
        let state = || async { resolve_quarantine(d, &q, Utc::now()).await.unwrap().state };
        assert_eq!(state().await, QuarantineState::Withheld, "I4182: withheld");
        withdraw_countersign(d, &row, &o1, &o2, "I4182").await;
        assert_ne!(
            state().await,
            QuarantineState::Withheld,
            "I4182: a withdrawn countersign withholds nothing from then on"
        );
        put(d, &e2::voice_of(&st, &o2), "I4182").await;
        assert_eq!(
            state().await,
            QuarantineState::Withheld,
            "I4182: o2's countersign withholds again"
        );

        // ── I4183: a stranger may not withdraw it.
        let st = verdict(at + Duration::minutes(15));
        let row = conclude(d, &st, &o1, true, "I4183").await;
        if let Ok(StatementOutcome::Row { .. }) = e2::put_statement(d, &withdrawal(&x, &row)).await
        {
            panic!("I4183: a stranger's withdraws landed");
        }
        assert!(
            d.get_attestation(&row.attestation_id)
                .await
                .unwrap()
                .is_some(),
            "I4183: the act still stands"
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
    async fn i4180_an_official_withdraws_its_countersign_alone_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        crate::federation::hard_case::test_support::declare_node(&b, "cw-node").await;
        Box::pin(super::bodies::i4180_an_official_withdraws_its_countersign_alone(&b, &suffix()))
            .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i4180_an_official_withdraws_its_countersign_alone_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        crate::federation::hard_case::test_support::declare_node(&b, "cw-node").await;
        Box::pin(super::bodies::i4180_an_official_withdraws_its_countersign_alone(&b, &suffix()))
            .await;
        eprintln!("i4180 postgres: RAN");
    }
}
