//! v56.0.0 (CIRISPersist#934 step 1, door 4) — **a re-seal judges the row it
//! writes over, not a row it read earlier.**
//!
//! `reseal_attestation_v31` reads the stored row, gates the re-seal against it
//! (`migration::check_reseal_admission`: a re-seal changes the SEAL, never the
//! row's meaning or placement), then writes. Before v56.0.0 sqlite and
//! postgres read the row through `get_attestation` BEFORE their write
//! transaction and asked nothing inside it; memory re-asked the shape gate on
//! the row it found under its lock. A change landing between the read and the
//! write was therefore judged on memory and overwritten on the SQL backends.
//!
//! I953 — one body, memory, sqlite, postgres. A local `delegates_to` is staged;
//! a re-seal of it (adding an envelope member) is paused after its read, at the
//! test-only `reseal_before_write` seam; the row crosses to the federation tier
//! (`enter_mesh`) while it waits; then the re-seal resumes. It must be refused
//! (its placement no longer matches the row it would overwrite) and the
//! crossed row must not carry the re-seal's envelope. A control leg first
//! re-seals a second staged row with no race, so the refusal is the race's.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::delegation_cycle_invariants::bodies::{agent, stage_local_edge};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::attestation_tier;
    use crate::federation::FederationDirectory;
    use crate::store::test_hooks::Pause;

    async fn while_paused<T>(
        pause: &Pause,
        rival: impl std::future::Future<Output = T>,
    ) -> (T, bool) {
        pause.reached().await;
        tokio::pin!(rival);
        match tokio::time::timeout(std::time::Duration::from_secs(3), &mut rival).await {
            Ok(out) => {
                pause.resume();
                (out, true)
            }
            Err(_) => {
                pause.resume();
                (rival.await, false)
            }
        }
    }

    fn restamped(
        row: &crate::federation::Attestation,
        signer: &str,
    ) -> crate::federation::Attestation {
        let mut r = row.clone();
        r.attestation_envelope["restamped"] = serde_json::json!(true);
        ts::seal_row_in_place(signer, &mut r);
        // The stored column is canonical at rest (#647); sign those bytes.
        crate::federation::canonical_at_rest::canonicalize_in_place(&mut r.attestation_envelope)
            .expect("canonical");
        let (och, sc, sp) = ts::sign_envelope(signer, &r.attestation_envelope);
        r.original_content_hash = och;
        r.scrub_signature_classical = sc;
        r.scrub_signature_pqc = sp;
        r
    }

    pub(crate) async fn i953_a_reseal_judges_the_row_it_overwrites(
        d: &dyn FederationDirectory,
        pause: std::sync::Arc<Pause>,
        tag: &str,
    ) {
        let k = |n: &str| format!("{tag}-{n}");
        for n in ["a", "b", "c", "e"] {
            agent(d, &k(n)).await;
        }

        // Control: with no race, the same kind of re-seal of a staged row lands.
        let (cid, _, _) = stage_local_edge(d, &k("c"), &k("e")).await;
        let cstored = d.get_attestation(&cid).await.unwrap().expect("control row");
        // The control must not trip the armed seam: run it on a fresh pause
        // point by resuming in advance (a stored permit lets it pass at once).
        pause.resume();
        let landed = d
            .reseal_attestation_v31(&restamped(&cstored, &k("c")))
            .await
            .expect("control: a re-seal of a staged row with no race is admitted");
        assert!(landed, "control: the re-seal rewrote the row");
        // The control consumed the armed pause; the race below re-arms nothing,
        // so the caller arms a second pause for it (see the runners).
    }

    pub(crate) async fn i953_race(
        d: &dyn FederationDirectory,
        pause: std::sync::Arc<Pause>,
        tag: &str,
    ) {
        let k = |n: &str| format!("{tag}-{n}");
        let (id, ci, custody) = stage_local_edge(d, &k("a"), &k("b")).await;
        let stored = d.get_attestation(&id).await.unwrap().expect("staged row");
        assert_eq!(stored.tier, attestation_tier::LOCAL);
        let reseal = restamped(&stored, &k("a"));

        let (resealed, (crossed, crossed_free)) = tokio::join!(
            d.reseal_attestation_v31(&reseal),
            while_paused(&pause, d.enter_mesh(&id, &ci, &custody)),
        );
        assert!(
            crossed_free,
            "I953: the crossing must run while the re-seal is paused before its write"
        );
        crossed.expect("I953: the crossing lands while the re-seal waits");
        let after = d.get_attestation(&id).await.unwrap().expect("row");
        assert_eq!(
            after.tier,
            attestation_tier::FEDERATION,
            "I953: the row crossed"
        );
        let overwritten = after.attestation_envelope.get("restamped").is_some();
        match &resealed {
            Err(e) if e.to_string().contains("diverges from the stored") && !overwritten => {}
            other => {
                panic!(
                "I953: the re-seal read the LOCAL row, the row then crossed, and the re-seal must \
                 be judged against the row it would overwrite. Got {other:?}; the crossed row \
                 (tier {}) {} the re-seal's envelope",
                after.tier,
                if overwritten { "NOW CARRIES" } else { "does not carry" }
            )
            }
        }
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn tag() -> String {
        format!("i953-{}", uuid::Uuid::new_v4().simple())
    }

    macro_rules! i953 {
        ($b:expr) => {{
            let b = $b;
            let d = &b as &dyn crate::federation::FederationDirectory;
            let t = tag();
            let p = b.test_hooks().arm_pause("reseal_before_write");
            super::bodies::i953_a_reseal_judges_the_row_it_overwrites(d, p, &t).await;
            let p = b.test_hooks().arm_pause("reseal_before_write");
            super::bodies::i953_race(d, p, &t).await;
        }};
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i953_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        i953!(b);
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i953_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("i953_postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        i953!(b);
        eprintln!("i953_postgres: RAN");
    }
}
