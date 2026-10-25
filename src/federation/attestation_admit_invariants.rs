//! v56.0.0 (CIRISPersist#934 step 1) — **the shared attestation plan judges
//! at the two instants it is given.**
//!
//! The Constitution's review of #934 (2026-10-13, condition 1): a plan is pure
//! over reads at instants that are INPUTS, so `V(rows, t)` is a replay of plans
//! (CIRISConstitution#131 §2–§3, CIRISServer `FSD/TOPOLOGY.md` §4.1).
//! [`plan_put_attestation`](super::attestation_admit::plan_put_attestation)
//! takes [`PlanInstants`](super::attestation_admit::PlanInstants) — `fold_at`
//! (the row's signed instant) and `received_at` (the receiver's clock) — and
//! reads no clock.
//!
//! I950 — one body, run on memory, sqlite and postgres. The SAME signed row,
//! planned under two instant pairs, gets the verdict each gate's instant
//! implies, and the plan writes nothing either time:
//!
//! - (1) a receipt bound on `received_at` (`check_instant_binding`): a row
//!   signed an hour ahead of `t0` is refused at `received_at = t0` and
//!   admitted at `received_at = t0 + 1h`, with `fold_at` its own instant both
//!   times;
//! - (2) a fold still at receipt (`check_delegation_cycle_admission`, a
//!   #1049 candidate): with `c → e` live until `t0 + 1h`, `e → c` closes a
//!   cycle at `received_at = t0` and nothing at `t0 + 2h`;
//! - (3) a fold on `fold_at` (`check_community_trust_grant_admission`, the
//!   owner bindings in force): with the owner's binding signed at
//!   2026-05-01, a capture grant is refused at `fold_at` a month earlier and
//!   admitted at `fold_at` a day later, with `received_at` the same both
//!   times.
//!
//! Swapping the two instants inside the receipt bound turns (1) red, and
//! inside the fold turns (3) red, on all three backends.
//!
//! I952 — the hybrid-completion door (`attach_attestation_pqc_signature`),
//! decided once by `plan_attach_attestation_pqc_signature`: an unknown id is
//! refused `InvalidArgument`; a second completion of a completed row is the
//! PLAN's `Conflict` ("already PQC-complete"), not the storage guard's
//! ("concurrently completed"), so the guard does not hide a lost decision; a
//! completion stores the caller's half and a completion instant.

/// The backend-agnostic witness bodies.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::attestation_admit::{
        plan_put_attestation, AttestationPlan, AttestationStore, PlanInstants,
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

    fn at(
        fold_at: chrono::DateTime<chrono::Utc>,
        received_at: chrono::DateTime<chrono::Utc>,
    ) -> PlanInstants {
        PlanInstants {
            fold_at,
            received_at,
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

        // (1) the future-skew bound, judged at `received_at`.
        let ahead = edge(&k("a"), &k("b"), t0 + hour);
        let id = ahead.attestation.attestation_id.clone();
        let signed = ahead.attestation.asserted_at;
        let early =
            plan_put_attestation(d, ahead.clone(), &WriteOrigin::Wire, at(signed, t0)).await;
        match &early {
            Err(Error::InvalidArgument(m)) if m.contains("ahead of now") => {}
            other => panic!(
                "(1) a row signed 1h ahead of t0, received AT t0, must be refused by the skew \
                 bound; got {}",
                verdict(other)
            ),
        }
        let on_time =
            plan_put_attestation(d, ahead, &WriteOrigin::Wire, at(signed, t0 + hour)).await;
        assert!(
            matches!(on_time, Ok(AttestationPlan::Insert(_))),
            "(1) the same row received at its own signed instant is inside the skew bound; got {}",
            verdict(&on_time)
        );
        assert!(
            dd.get_attestation(&id).await.unwrap().is_none(),
            "(1) a plan writes nothing"
        );

        // (2) a fold still at receipt: `c → e` is live until t0 + 1h.
        ts::put_delegates_to(dd, &k("c"), &k("e"), Some(t0 + hour))
            .await
            .expect("(2) c → e, expiring at t0 + 1h");
        let closing = edge(&k("e"), &k("c"), t0);
        let id = closing.attestation.attestation_id.clone();
        let live = plan_put_attestation(d, closing.clone(), &WriteOrigin::Wire, at(t0, t0)).await;
        match &live {
            Err(Error::DelegationCycle { hops, .. }) => assert_eq!(*hops, 1, "(2) hops"),
            other => panic!(
                "(2) received at t0, c → e is live, so e → c closes a cycle; got {}",
                verdict(other)
            ),
        }
        let expired =
            plan_put_attestation(d, closing, &WriteOrigin::Wire, at(t0, t0 + hour * 2)).await;
        assert!(
            matches!(expired, Ok(AttestationPlan::Insert(_))),
            "(2) received at t0 + 2h, c → e has expired, so e → c closes nothing; got {}",
            verdict(&expired)
        );
        assert!(
            dd.get_attestation(&id).await.unwrap().is_none(),
            "(2) a plan writes nothing"
        );

        // (3) a fold on `fold_at`: the owner bindings in force over the node.
        let (owner, node) = (k("owner"), k("node"));
        ts::register_identity_key(dd, &owner, identity_type::USER).await;
        ts::register_hybrid_key_as(dd, &node, &node, identity_type::NODE).await;
        dd.put_attestation(SignedAttestation {
            attestation: ts::owner_binding_attestation(&k("ob"), &owner, &node),
        })
        .await
        .expect("(3) the owner binds the node");
        let gid = uuid::Uuid::new_v4().to_string();
        let mut grant = ts::bare_attestation(
            &gid,
            &node,
            &node,
            &serde_json::json!({
                "id": gid,
                "dimension": crate::federation::community_trust_consent::COMMUNITY_TRUST_DIMENSION,
                "score": 1.0,
            }),
        );
        grant.attestation_type = attestation_type::SCORES.to_owned();
        // v59.0.0 (CIRISPersist#1096) — the node, its owner and the agent key.
        let agent = k("agent");
        ts::register_hybrid_key(dd, &agent).await;
        grant.subject_key_ids = vec![node.clone(), owner.clone(), agent];
        ts::seal_row_in_place(&node, &mut grant);
        let grant = SignedAttestation { attestation: grant };
        let now = truncate(chrono::Utc::now());
        // `owner_binding_attestation` signs its binding at 2026-05-01.
        let bound: chrono::DateTime<chrono::Utc> = "2026-05-01T00:00:00Z".parse().unwrap();
        let before = plan_put_attestation(
            d,
            grant.clone(),
            &WriteOrigin::Wire,
            at(bound - chrono::Duration::days(30), now),
        )
        .await;
        match &before {
            Err(Error::InvalidArgument(m)) if m.contains("no owner binding") => {}
            other => panic!(
                "(3) folded a month before the owner bound the node, the grant names no \
                 owner in force; got {}",
                verdict(other)
            ),
        }
        let after = plan_put_attestation(
            d,
            grant,
            &WriteOrigin::Wire,
            at(bound + chrono::Duration::days(1), now),
        )
        .await;
        assert!(
            matches!(after, Ok(AttestationPlan::Insert(_))),
            "(3) folded a day after, the owner's binding is in force; got {}",
            verdict(&after)
        );
        assert!(
            dd.get_attestation(&gid).await.unwrap().is_none(),
            "(3) a plan writes nothing"
        );
    }
}

/// I952's body, on any directory.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod pqc_bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::{Error, FederationDirectory};

    pub(crate) async fn i952_the_completion_is_decided_once(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let owner = format!("owner-{tag}");
        let node = format!("node-{tag}");
        let id = uuid::Uuid::new_v4().to_string();
        ts::register_identity_key(d, &owner, crate::federation::types::identity_type::USER).await;
        ts::register_hybrid_key(d, &node).await;

        // (1) nothing held under the id.
        match d
            .attach_attestation_pqc_signature(&uuid::Uuid::new_v4().to_string(), "sig")
            .await
        {
            Err(Error::InvalidArgument(m)) if m.contains("does not exist") => {}
            other => panic!("(1) an unknown id is refused InvalidArgument; got {other:?}"),
        }

        // (3) a pending row completes with the caller's half.
        let mut row = ts::owner_binding_attestation(&id, &owner, &node);
        let pqc_sig = row.scrub_signature_pqc.clone().expect("a PQC half");
        row.pqc_completed_at = None;
        d.put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await
            .expect("the pending row");
        d.attach_attestation_pqc_signature(&id, &pqc_sig)
            .await
            .expect("(3) the completion");
        let stored = d.get_attestation(&id).await.unwrap().expect("(3) held");
        assert_eq!(
            stored.scrub_signature_pqc.as_deref(),
            Some(pqc_sig.as_str()),
            "(3)"
        );
        assert!(
            stored.pqc_completed_at.is_some(),
            "(3) a completion instant"
        );

        // (2) completing it again is the plan's refusal.
        match d.attach_attestation_pqc_signature(&id, &pqc_sig).await {
            Err(Error::Conflict(m)) if m.contains("already PQC-complete") => {}
            other => panic!(
                "(2) a completed row is refused by the plan (\"already PQC-complete\"), not \
                 left to the storage guard; got {other:?}"
            ),
        }
    }
}

#[cfg(test)]
mod run {
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
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
        super::pqc_bodies::i952_the_completion_is_decided_once(&b, &format!("i952-{}", suffix()))
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
        super::pqc_bodies::i952_the_completion_is_decided_once(&b, &format!("i952-{}", suffix()))
            .await;
        eprintln!("i950_postgres: RAN");
    }
}
