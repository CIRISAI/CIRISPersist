//! v62.0.0 (PT-fix1; CC 4.4.3.12 as ruled 11-21, CC 5.3.4) — **the
//! rootless serve wait's party answer names a one-seat affiliation's
//! designated officials** (`serve::is_party_to_row`'s officials arm, which
//! calls `group_serve::served_to_floor_official`, the one implementation).
//! sqlite and postgres, on a ROOTLESS node.
//!
//! Why the witness is UNIT-level, on `is_party_to_row` itself: through the
//! serve listing the arm is unobservable. `serve::servable_by_own_rule` asks
//! `served_to_floor_official` directly (every placement, rooted or not), and
//! an official that voiced the act is already a party as a voice signer. So
//! removing the arm would leave every serve result unchanged; asserting the
//! party answer directly, for an official that did NOT voice the act, is what
//! fails when the arm is removed.
//!
//! - **I4155** — on a rootless node holding a concluded countersigned
//!   slashing (the seat `f` and official `o1`), `is_party_to_row` answers
//!   `true` for the room's OTHER designated official `o2` (no voice of its
//!   own, not attester or subject) and `false` for a stranger. The serve
//!   listing also reaches `o2` (through the direct call; asserted, not the
//!   arm's witness).

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::edition2::names::RowId;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_room_with_blob, id_of, reg,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, cohort_scope};
    use crate::federation::FederationDirectory;
    use chrono::{Duration, Utc};

    pub(crate) async fn i4155_the_wait_names_the_officials(d: &dyn FederationDirectory, s: &str) {
        let k = |n: &str| format!("i4155-{n}-{s}");
        let (f, o1, o2, m, x, solo) = (k("f"), k("o1"), k("o2"), k("m"), k("x"), k("solo"));
        reg(d, &[&f, &o1, &o2, &m, &x, &solo]).await;
        let (f, o1, o2, m, x, solo) = (
            id_of(&f),
            id_of(&o1),
            id_of(&o2),
            id_of(&m),
            id_of(&x),
            id_of(&solo),
        );
        let mut blob = serde_json::json!({
            crate::federation::affiliation_config::POLICY_COHORT_FIELD: "affiliations",
        });
        blob[crate::federation::affiliation_config::POLICY_AFFILIATION_CONFIG_FIELD] = serde_json::json!({
            "designated_officials": [
                { "role": "privacy_officer", "key_id": o1 },
                { "role": "records_officer", "key_id": o2 },
            ],
        });
        found_room_with_blob(d, &solo, "founder_only", &[&f], &[], Some(blob))
            .await
            .expect("I4155: a sole practitioner's affiliation with two officials");
        assert!(
            !crate::federation::edition2::serve::this_node_is_rooted(d)
                .await
                .unwrap(),
            "I4155 precondition: the node reaches no root (the rootless wait applies)"
        );
        let env = serde_json::json!({
            "dimension": "slashing:proven_rogue:v1",
            "score": 1.0,
            "confidence": 1.0,
            "community_id": solo,
            "payload": {},
        });
        let mut r = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), &f, &m, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = cohort_scope::FEDERATION.into();
        r.subject_key_ids = vec![m.clone()];
        r.asserted_at = Utc::now() - Duration::hours(1);
        let st = e2::counted_statement_of(&r, &f);
        let rid = RowId::of_statement(&st).expect("a row statement");
        e2::put_statement(d, &st)
            .await
            .expect("I4155: the seat's voice");
        let out = e2::put_statement(d, &e2::voice_of(&st, &o1))
            .await
            .expect("I4155: o1's countersign");
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "I4155: the act concludes: {out:?}"
        );
        let parties = [f.as_str(), m.as_str()];
        assert!(
            crate::federation::edition2::serve::is_party_to_row(d, &st, &o2, &parties)
                .await
                .unwrap(),
            "I4155: the room's other designated official is a party to the act (the arm)"
        );
        assert!(
            !crate::federation::edition2::serve::is_party_to_row(d, &st, &x, &parties)
                .await
                .unwrap(),
            "I4155: a stranger is no party"
        );
        let mut served = Vec::new();
        let mut cursor = None;
        loop {
            let page = crate::federation::edition2::serve::statements_served_to(
                d,
                cursor.as_ref(),
                256,
                Some(&o2),
            )
            .await
            .unwrap();
            let Some(next) = page.next else { break };
            cursor = Some(next);
            served.extend(page.statements.into_iter().map(|st| st.bytes));
        }
        assert!(
            served
                .iter()
                .any(|b| RowId::of_statement(b).as_ref() == Some(&rid)),
            "I4155: the rootless node serves the concluded act to o2 (the direct call)"
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
    async fn i4155_the_wait_names_the_officials_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        crate::federation::hard_case::test_support::declare_node(&b, "fp-node").await;
        Box::pin(super::bodies::i4155_the_wait_names_the_officials(
            &b,
            &suffix(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i4155_the_wait_names_the_officials_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        crate::federation::hard_case::test_support::declare_node(&b, "fp-node").await;
        Box::pin(super::bodies::i4155_the_wait_names_the_officials(
            &b,
            &suffix(),
        ))
        .await;
        eprintln!("i4155 postgres: RAN");
    }
}
