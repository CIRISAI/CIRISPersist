//! v56.0.0 (CIRISPersist#934 step 1, door 6) — **the genesis re-bake purge
//! door refuses, at the store, an id the bundle does not carry.**
//!
//! `purge_genesis_delegation_row_v31` bypasses the general purge gate
//! (`migration::check_purge_admission`) because two of the three genesis
//! delegation rows are `delegates_to`. Its own, narrower gate
//! (`genesis::check_genesis_rebake_purge_admission_under`) is what keeps the
//! bypass from being a delete door for any row: the id must be one the
//! compiled-in bundle carries, or one a quorum-verified bundle names.
//!
//! The gate had a unit witness (`the_purge_door_widens_under_quorum_and_only_
//! under_quorum_671`) that calls the predicate directly. Nothing called the
//! STORE door with an inadmissible id, so deleting the gate from the door
//! (the shared `purge_genesis_delegation_row_planned` since v56.0.0, each
//! backend's own body before it) left every test green. I954 is that call.
//!
//! I954 — one body, memory, sqlite, postgres. An ordinary staged
//! `delegates_to` row (not a genesis id) is offered to the genesis door with
//! its real `persist_row_hash` under `CompiledIn`: it is refused
//! `InvalidArgument` naming #665/#671, and the row is still there. A control
//! leg offers a baked genesis id the store does not hold: admitted by the
//! gate, nothing to delete, `Ok(false)` — so the refusal is the gate's, not
//! the delete's.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::delegation_cycle_invariants::bodies::{agent, stage_local_edge};
    use crate::federation::genesis::bundle::GenesisPurgeAuthority;
    use crate::federation::{Error, FederationDirectory};

    pub(crate) async fn i954_the_genesis_door_refuses_an_id_the_bundle_does_not_carry(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let k = |n: &str| format!("{tag}-{n}");
        for n in ["a", "b"] {
            agent(d, &k(n)).await;
        }

        // Control: a baked id passes the gate; the store holds no such row.
        let absent = d
            .purge_genesis_delegation_row_v31(
                "genesis-charter",
                "no-such-row-hash",
                &GenesisPurgeAuthority::CompiledIn,
            )
            .await
            .expect("I954 control: a baked genesis id is admitted by the door's gate");
        assert!(!absent, "I954 control: nothing was held, nothing deleted");

        let (id, _, _) = stage_local_edge(d, &k("a"), &k("b")).await;
        let stored = d.get_attestation(&id).await.unwrap().expect("staged row");
        let got = d
            .purge_genesis_delegation_row_v31(
                &id,
                &stored.persist_row_hash,
                &GenesisPurgeAuthority::CompiledIn,
            )
            .await;
        let still = d.get_attestation(&id).await.unwrap();
        match &got {
            Err(Error::InvalidArgument(m)) if m.contains("#665/#671") && still.is_some() => {}
            other => panic!(
                "I954: an ordinary row ({id}) is not a genesis delegation id and no verified \
                 bundle names it; the genesis re-bake door must refuse it at the store. Got \
                 {other:?}; the row is {}",
                if still.is_some() {
                    "still held"
                } else {
                    "GONE"
                }
            ),
        }
    }
}

#[cfg(test)]
mod run {
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn tag() -> String {
        format!("i954-{}", uuid::Uuid::new_v4().simple())
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i954_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i954_the_genesis_door_refuses_an_id_the_bundle_does_not_carry(&b, &tag())
            .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i954_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("i954_postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i954_the_genesis_door_refuses_an_id_the_bundle_does_not_carry(&b, &tag())
            .await;
        eprintln!("i954_postgres: RAN");
    }
}
