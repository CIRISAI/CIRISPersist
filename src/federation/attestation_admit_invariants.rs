//! v56.0.0 (CIRISPersist#934 step 1) — **the shared attestation plan judges
//! at the instant it is given.**
//!
//! The Constitution's review of #934 (2026-10-13, condition 1): a plan is pure
//! over reads at an instant that is an INPUT, so `V(rows, t)` is a replay of
//! plans (CIRISConstitution#131 §2–§3, CIRISServer `FSD/TOPOLOGY.md` §4.1).
//! [`plan_put_attestation`](super::attestation_admit::plan_put_attestation)
//! takes `at` and reads no clock; the door samples the receipt clock once and
//! passes it in.
//!
//! I950 — one body, run on memory, sqlite and postgres. The SAME signed row,
//! planned at two instants, gets the verdict each instant implies, and the
//! plan writes nothing either time:
//!
//! - (1) the future-skew bound (`check_instant_binding`): a row whose signed
//!   `asserted_at` is an hour ahead of `t0` is refused at `t0` and admitted at
//!   `t0 + 1h`;
//! - (2) a directory fold judged at `at` (`check_delegation_cycle_admission`):
//!   with `a → b` live until `t0 + 1h`, the edge `b → a` closes a cycle at
//!   `t0` and closes nothing at `t0 + 2h`, when `a → b` has expired.
//!
//! Mutating either gate's instant back to the clock turns (1) or (2) red on
//! all three backends.

/// The backend-agnostic witness bodies.
#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::attestation_admit::{
        plan_put_attestation, AttestationPlan, AttestationStore,
    };
    use crate::federation::replication::admission::WriteOrigin;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type};
    use crate::federation::{Error, FederationDirectory, SignedAttestation};

    fn truncate(t: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
        crate::federation::admission::truncate_to_substrate_resolution(t)
    }

    /// A `delegates_to(granter → grantee)` signed by `granter`, asserted at
    /// `asserted_at`. Not stored.
    fn edge(
        granter: &str,
        grantee: &str,
        asserted_at: chrono::DateTime<chrono::Utc>,
    ) -> SignedAttestation {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "references_attestation_id": id,
            "scope": ["act_on_behalf"],
        });
        let mut row = ts::bare_attestation(&id, granter, grantee, &envelope);
        row.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        row.asserted_at = asserted_at;
        row.scrub_timestamp = asserted_at;
        ts::seal_row_in_place(granter, &mut row);
        SignedAttestation { attestation: row }
    }

    /// What a plan decided, as a word a failure message can print.
    fn verdict(r: &Result<AttestationPlan, Error>) -> String {
        match r {
            Ok(AttestationPlan::Insert(_)) => "Insert".to_owned(),
            Ok(AttestationPlan::AlreadyHeld) => "AlreadyHeld".to_owned(),
            Ok(AttestationPlan::ComposerReplay { .. }) => "ComposerReplay".to_owned(),
            Err(e) => format!("Err({e})"),
        }
    }

    pub(crate) async fn i950_the_plan_judges_at_its_input_instant<D>(d: &D, tag: &str)
    where
        D: AttestationStore + 'static,
    {
        let dd = d as &dyn FederationDirectory;
        let k = |n: &str| format!("{tag}-{n}");
        for n in ["a", "b", "c", "e"] {
            ts::register_hybrid_key_as(dd, &k(n), &k(n), identity_type::AGENT).await;
        }
        let t0 = truncate(chrono::Utc::now());
        let hour = chrono::Duration::hours(1);

        // (1) the future-skew bound, judged at `at`.
        let ahead = edge(&k("a"), &k("b"), t0 + hour);
        let id = ahead.attestation.attestation_id.clone();
        let at_t0 = plan_put_attestation(d, ahead.clone(), &WriteOrigin::Wire, t0).await;
        match &at_t0 {
            Err(Error::InvalidArgument(m)) if m.contains("ahead of now") => {}
            other => panic!(
                "(1) a row signed 1h ahead of t0, planned AT t0, must be refused by the skew \
                 bound; got {}",
                verdict(other)
            ),
        }
        let at_t1 = plan_put_attestation(d, ahead, &WriteOrigin::Wire, t0 + hour).await;
        assert!(
            matches!(at_t1, Ok(AttestationPlan::Insert(_))),
            "(1) the same row planned AT its own signed instant is inside the skew bound; got {}",
            verdict(&at_t1)
        );
        assert!(
            dd.get_attestation(&id).await.unwrap().is_none(),
            "(1) a plan writes nothing"
        );

        // (2) a directory fold judged at `at`: `c → e` is live until t0 + 1h.
        ts::put_delegates_to(dd, &k("c"), &k("e"), Some(t0 + hour))
            .await
            .expect("(2) c → e, expiring at t0 + 1h");
        let closing = edge(&k("e"), &k("c"), t0);
        let id = closing.attestation.attestation_id.clone();
        let live = plan_put_attestation(d, closing.clone(), &WriteOrigin::Wire, t0).await;
        match &live {
            Err(Error::DelegationCycle { hops, .. }) => assert_eq!(*hops, 1, "(2) hops"),
            other => panic!(
                "(2) at t0, c → e is live, so e → c closes a cycle; got {}",
                verdict(other)
            ),
        }
        let expired = plan_put_attestation(d, closing, &WriteOrigin::Wire, t0 + hour * 2).await;
        assert!(
            matches!(expired, Ok(AttestationPlan::Insert(_))),
            "(2) at t0 + 2h, c → e has expired, so e → c closes nothing; got {}",
            verdict(&expired)
        );
        assert!(
            dd.get_attestation(&id).await.unwrap().is_none(),
            "(2) a plan writes nothing"
        );
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i950_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        super::bodies::i950_the_plan_judges_at_its_input_instant(&b, &format!("i950-{}", suffix()))
            .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i950_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i950_the_plan_judges_at_its_input_instant(&b, &format!("i950-{}", suffix()))
            .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i950_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("i950_postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i950_the_plan_judges_at_its_input_instant(&b, &format!("i950-{}", suffix()))
            .await;
        eprintln!("i950_postgres: RAN");
    }
}
