//! v54.0.0 (Codex round 2 on PR #1050) — **no postgres door checks out a
//! second pooled client while it holds one.**
//!
//! A door that holds a pooled client (and, worse, an open transaction on it)
//! and then calls a directory method that takes ANOTHER client waits for a
//! connection only it can release. On a one-connection pool, or a pool every
//! connection of which is held by such a door, that wait never ends: the
//! caller hangs and nothing reports it. A roomy test pool hides the nesting
//! entirely, so these witnesses build the backend with a pool of ONE
//! connection and run each door under a timeout
//! that FAILS the test (a hang is the defect, never the test's own hang).
//!
//! - **I601** — the `signed_wire_index` re-index. v62.0.0: deleted with the
//!   content-hash wire index (an earlier serving surface; slice F).
//! - **I602** — the `delegates_to` cycle re-check. `put_attestation` and
//!   `enter_mesh` re-ran the cycle gate under the delegation advisory lock,
//!   inside the transaction holding the only client, and the gate's graph
//!   reads took another. A cycle-gated put and a crossing must both finish
//!   and land, and the cycle-closing edge must still be refused on the same
//!   one-connection pool (the re-check still runs, on the transaction).
//! - **I1480** (v59.1.2) — the pool itself: a default pool is never smaller
//!   than [`POOL_MAX_SIZE_FLOOR`](crate::store::postgres::POOL_MAX_SIZE_FLOOR)
//!   whatever the CPU count (deadpool's own default was 2 on a 1-vCPU node),
//!   and deadpool's own timers stay off (they panic on a thread without
//!   persist's reactor; I320).
//! - **I1481** (v59.1.2) — a starved pool is a TYPED error inside its wait,
//!   never a hang: the store, federation, audit and secrets arms each carry
//!   it as `PoolExhausted`.
//! - **I1482** (v59.1.2) — the doors the field wedge named hold one client
//!   and reach for a second no more: each finishes on a one-connection pool
//!   whose checkout gives up after [`SHORT_WAIT`] (a nested checkout answers
//!   `PoolExhausted`, so a regression fails fast instead of at the bound).
//!   v62.0.0: the wire-index point-read leg is deleted with the content-hash
//!   wire index; the occurrence-door leg stays.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::federation::delegation_cycle_invariants::bodies as dc;
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::tier_ingest::test_support as ts;
use crate::federation::{Error, FederationDirectory};
use crate::store::postgres::PostgresBackend;
use crate::store::Backend as _;

/// Long enough for every door on a cold one-connection pool, short enough
/// that a hang reports instead of eating the lane's budget.
const BOUND: std::time::Duration = std::time::Duration::from_secs(60);

/// v59.1.2 — the checkout wait on the I1481/I1482 pools: a nested checkout
/// fails inside it instead of hanging to [`BOUND`].
const SHORT_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// v59.1.2 — a migrated backend on its own database, `max_size` connections,
/// checkout wait [`SHORT_WAIT`].
async fn starved_backend(test: &str, max_size: usize) -> Option<PostgresBackend> {
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("{test}: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
        return None;
    };
    let b = PostgresBackend::connect_with_pool_for_test(&dsn, max_size, SHORT_WAIT)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    assert_eq!(
        b.pool_max_size_for_test(),
        max_size,
        "the witness's own premise"
    );
    eprintln!("{test}: RAN on {dsn} with a {max_size}-connection pool, wait {SHORT_WAIT:?}");
    Some(b)
}

fn suffix() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// A migrated backend on its own database whose pool holds ONE connection
/// (migrations run on their own, non-pooled connection).
async fn one_connection_backend(test: &str) -> Option<PostgresBackend> {
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("{test}: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
        return None;
    };
    let b = PostgresBackend::connect_with_max_size_for_test(&dsn, 1)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    assert_eq!(b.pool_max_size_for_test(), 1, "the witness's own premise");
    eprintln!("{test}: RAN on {dsn} with a one-connection pool");
    Some(b)
}

/// Run `door` under [`BOUND`]; a timeout is the nested checkout, named.
async fn within_bound<T>(what: &str, door: impl std::future::Future<Output = T>) -> T {
    match tokio::time::timeout(BOUND, door).await {
        Ok(out) => out,
        Err(_) => panic!(
            "{what}: did not finish within {BOUND:?} on a one-connection pool — the door \
             waits for a second pooled client while holding the only one"
        ),
    }
}

/// **I602** — see the module doc.
#[tokio::test(flavor = "multi_thread")]
async fn i602_the_cycle_recheck_completes_on_one_connection() {
    let Some(b) = one_connection_backend("i602").await else {
        return;
    };
    let d = &b as &dyn FederationDirectory;
    let tag = suffix();
    let (a, c) = (format!("i602-a-{tag}"), format!("i602-c-{tag}"));
    dc::agent(d, &a).await;
    dc::agent(d, &c).await;
    within_bound(
        "I602 a cycle-gated put",
        ts::put_delegates_to(d, &a, &c, None),
    )
    .await
    .expect("I602 a → c admits");
    assert!(dc::has_fed_edge(d, &a, &c).await, "I602 a → c is stored");
    // v62.0.0 (slice C) — the closing edge is admitted (CC 4.4.3.34: "Cycles are visited once"; the kernel's walk
    // visits a cycle once, so no edge is refused for closing one), and the put
    // still completes on one connection under the lock it takes.
    within_bound(
        "I602 the cycle-closing put",
        ts::put_delegates_to(d, &c, &a, None),
    )
    .await
    .expect("I602 c → a is admitted (v62: no edge refused for closing a cycle)");
    // A crossing of a gated edge takes the same lock and re-check.
    let (x, y) = (format!("i602-x-{tag}"), format!("i602-y-{tag}"));
    dc::agent(d, &x).await;
    dc::agent(d, &y).await;
    let (staged, ci, custody) = dc::stage_local_edge(d, &x, &y).await;
    within_bound(
        "I602 a cycle-gated crossing",
        b.enter_mesh(&staged, &ci, &custody),
    )
    .await
    .expect("I602 the crossing x → y admits");
    assert!(
        dc::has_fed_edge(d, &x, &y).await,
        "I602 the crossing landed at the federation tier"
    );
}

/// **I1480** — see the module doc. The sizing function directly, at the CPU
/// counts that matter: one vCPU (the field node), a mid-size host, and a
/// caller's explicit size, which is kept as given.
#[test]
fn i1480_a_default_pool_is_floored_and_bounded() {
    use crate::store::postgres::{pool_config, POOL_MAX_SIZE_FLOOR};
    for cpus in [0, 1, 2, 7, 8] {
        assert_eq!(
            pool_config(None, cpus).max_size,
            POOL_MAX_SIZE_FLOOR,
            "I1480 {cpus} CPU(s): the floor, not deadpool's 2 x CPUs"
        );
    }
    assert_eq!(
        pool_config(None, 12).max_size,
        24,
        "I1480 above the floor the CPU-derived size stands"
    );
    assert_eq!(
        POOL_MAX_SIZE_FLOOR, 16,
        "I1480 the floor the field fix chose"
    );
    assert_eq!(
        pool_config(Some(1), 1).max_size,
        1,
        "I1480 an explicit size is the caller's"
    );
    // No deadpool timer: it would panic on a thread without persist's
    // reactor (I320). The wait bound is `PostgresBackend::checkout`'s (I1481).
    let t = pool_config(None, 1).timeouts;
    assert_eq!(
        (t.wait, t.create, t.recycle),
        (None, None, None),
        "I1480 deadpool's own timers stay off"
    );
    assert_eq!(
        crate::store::postgres::POOL_WAIT_TIMEOUT,
        std::time::Duration::from_secs(30)
    );
}

/// **I1481** — see the module doc.
#[tokio::test(flavor = "multi_thread")]
async fn i1481_a_starved_pool_is_a_typed_error_not_a_hang() {
    let Some(b) = starved_backend("i1481", 1).await else {
        return;
    };
    let held = b.get_client().await.expect("I1481 the only connection");
    let started = std::time::Instant::now();
    match within_bound("I1481 a second checkout", b.get_client()).await {
        Err(crate::store::Error::PoolExhausted { waited }) => assert_eq!(waited, SHORT_WAIT),
        other => panic!(
            "I1481 a second checkout must be PoolExhausted: {:?}",
            other.map(|_| ())
        ),
    }
    // One wait, not one per retry attempt.
    assert!(
        started.elapsed() < SHORT_WAIT * 2,
        "I1481 exhaustion is not retried: {:?}",
        started.elapsed()
    );
    let e = within_bound(
        "I1481 a federation door",
        FederationDirectory::lookup_public_key(&b, "i1481-none"),
    )
    .await
    .expect_err("I1481 the door cannot check out");
    assert!(
        matches!(e, Error::PoolExhausted { waited } if waited == SHORT_WAIT),
        "I1481 a federation door keeps the type: {e:?}"
    );
    assert_eq!(e.kind(), "federation_pool_exhausted");
    let c = b.checkout().await.expect_err("I1481 checkout");
    #[cfg(feature = "cirisaudit")]
    {
        let a = crate::audit::Error::from(crate::store::postgres::CheckoutError::Exhausted {
            waited: SHORT_WAIT,
        });
        assert_eq!(a.kind(), "audit_pool_exhausted");
    }
    #[cfg(feature = "secrets")]
    {
        let s =
            crate::secrets::SecretsError::from(crate::store::postgres::CheckoutError::Exhausted {
                waited: SHORT_WAIT,
            });
        assert_eq!(s.kind(), "secrets_pool_exhausted");
    }
    assert!(
        matches!(c, crate::store::postgres::CheckoutError::Exhausted { waited } if waited == SHORT_WAIT),
        "I1481 {c:?}"
    );
    drop(held);
    let _free = within_bound("I1481 a checkout once one is free", b.get_client())
        .await
        .expect("I1481 the pool recovers");
}

/// **I1482** — the occurrence doors: the route projection and the re-index
/// each check out their own client after the occurrence lands.
#[tokio::test(flavor = "multi_thread")]
async fn i1482_occurrence_doors_complete_on_one_connection() {
    use crate::federation::types::{device_class, OccurrenceTransportBinding};
    use base64::Engine as _;
    let Some(b) = starved_backend("i1482-occ", 1).await else {
        return;
    };
    let d = &b as &dyn FederationDirectory;
    let tag = suffix();
    let (identity, occ) = (format!("i1482-id-{tag}"), format!("i1482-occ-{tag}"));
    // v62.0.0 (P1-fix4; CC rc21 3.3.6) — an agent's occurrence binds the
    // AGENT's own identity (a machine key is never an occurrence of a
    // person): identity and occurrence are both agent keys.
    let _ = e2::put_key(
        d,
        &identity,
        &[crate::federation::types::identity_type::AGENT],
    )
    .await;
    // v61 (CIRISPersist#1122) — an agent's occurrence projects no route.
    let _ = e2::put_key(d, &occ, &[crate::federation::types::identity_type::AGENT]).await;
    let (identity, occ) = (e2::kid(&identity), e2::kid(&occ));
    let b64 = base64::engine::general_purpose::STANDARD;
    let row = crate::federation::IdentityOccurrence {
        identity_key_id: identity.clone(),
        occurrence_key_id: occ.clone(),
        device_class: device_class::AGENT.into(),
        hardware_attestation: None,
        asserted_at: chrono::Utc::now(),
        valid_until: None,
        encryption_pubkeys: None,
        transport_binding: Some(OccurrenceTransportBinding {
            reticulum_x25519_pubkey_base64: b64.encode([0x21; 32]),
            reticulum_ed25519_pubkey_base64: b64.encode([0x22; 32]),
            destination_hash_base64: b64.encode([0x21; 16]),
            app_name: "ciris.federation".into(),
            aspects: vec!["announce".into()],
        }),
        persist_row_hash: String::new(),
    };
    within_bound(
        "I1482 put_identity_occurrence_local",
        b.test_seam_put_identity_occurrence(row),
    )
    .await
    .expect("I1482 the local occurrence lands and projects its route");
    assert_eq!(
        b.list_transport_destinations_for(&occ).await.unwrap().len(),
        1,
        "I1482 the route projection ran"
    );
}

/// **I1570** (v61, CIRISPersist#1166) — every family of Postgres checkouts
/// runs the bounded checkout: on a one-connection pool whose only connection
/// is held, a door of each family answers an exhausted pool inside the
/// checkout wait, never a hang. Before v61 these families called the pool's
/// own `get()`, which waits without a bound (`store::pool_checkout_gate`
/// now refuses that from disk). A family whose error has no typed
/// `PoolExhausted` arm carries the exhaustion in its text.
#[tokio::test(flavor = "multi_thread")]
async fn i1570_every_checkout_family_answers_an_exhausted_pool_inside_the_wait() {
    use crate::outbound::OutboundQueue as _;
    use crate::read::ReadEngine as _;
    let Some(b) = starved_backend("i1570", 1).await else {
        return;
    };
    let held = b.checkout().await.expect("I1570 the only connection");
    let mut answered = Vec::new();
    // Each door must refuse inside the wait, and say why.
    async fn refused<T, E: std::fmt::Display>(
        family: &str,
        answered: &mut Vec<String>,
        door: impl std::future::Future<Output = Result<T, E>>,
    ) {
        let started = std::time::Instant::now();
        let e = match within_bound(family, door).await {
            Ok(_) => panic!("I1570 {family}: a door ran on a pool whose only connection is held"),
            Err(e) => e.to_string(),
        };
        assert!(
            started.elapsed() < SHORT_WAIT * 2,
            "I1570 {family}: answered after {:?}, past the checkout wait",
            started.elapsed()
        );
        assert!(
            e.to_lowercase().contains("exhausted"),
            "I1570 {family}: the refusal does not name the exhausted pool: {e}"
        );
        answered.push(family.to_owned());
    }
    refused("outbound", &mut answered, b.sweep_ack_timeouts()).await;
    refused(
        "read",
        &mut answered,
        b.list_federation_keys(
            crate::ceg::list::federation::FederationKeyFilter::default(),
            None,
            10,
            crate::scope::CallerScope::Unauthenticated,
        ),
    )
    .await;
    #[cfg(feature = "cirislens_sequence")]
    {
        use crate::sequence::SequenceService as _;
        refused(
            "sequence",
            &mut answered,
            b.next_sequence("i1570-identity", "i1570-stream"),
        )
        .await;
    }
    #[cfg(feature = "cirislens_occurrence")]
    {
        use crate::occurrence::OccurrenceService as _;
        refused(
            "occurrence",
            &mut answered,
            b.register_occurrence("i1570-occ", "i1570-identity", 60, None),
        )
        .await;
    }
    #[cfg(feature = "cirislens_maintenance_locks")]
    {
        use crate::maintenance_locks::MaintenanceLockService as _;
        refused(
            "maintenance_locks",
            &mut answered,
            b.try_acquire_lock("i1570-lock", "i1570", 10, None),
        )
        .await;
    }
    #[cfg(feature = "cirisaudit")]
    {
        refused(
            "retention",
            &mut answered,
            crate::retention::postgres::storage_summary_pg_with(&b, false),
        )
        .await;
        // The audit Merkle store holds the bare pool and checks out through
        // `checkout_bounded` on its own runtime.
        // v62.0.0 (P8) — the store is async; the read is awaited in place.
        let store = crate::audit::merkle_store::PgMerkleStore::from_backend(&b, "i1570");
        let started = std::time::Instant::now();
        let e = store
            .tree_size()
            .await
            .expect_err("I1570 merkle: a store read ran on a held pool")
            .to_string();
        assert!(
            started.elapsed() < SHORT_WAIT * 2 && e.to_lowercase().contains("exhausted"),
            "I1570 merkle: {e} after {:?}",
            started.elapsed()
        );
        answered.push("merkle".to_owned());
    }
    drop(held);
    eprintln!("I1570: bounded on {answered:?}");
}
