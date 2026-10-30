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
//! - **I601** — the `signed_wire_index` re-index. `index_stored_record` held
//!   its client and transaction while `entry_as_stored` reloaded the stored
//!   bytes through the directory's reads, each of which takes a client. A
//!   key registration and an attestation put each re-index after their
//!   primary write; both must finish, AND the index must hold the record (a
//!   re-index failure is logged, not returned, so finishing alone proves
//!   nothing).
//! - **I602** — the `delegates_to` cycle re-check. `put_attestation` and
//!   `enter_mesh` re-ran the cycle gate under the delegation advisory lock,
//!   inside the transaction holding the only client, and the gate's graph
//!   reads took another. A cycle-gated put and a crossing must both finish
//!   and land, and the cycle-closing edge must still be refused on the same
//!   one-connection pool (the re-check still runs, on the transaction).
//! - **I1480** (v59.1.2) — the pool itself: a default pool is never smaller
//!   than [`POOL_MAX_SIZE_FLOOR`](crate::store::postgres::POOL_MAX_SIZE_FLOOR)
//!   whatever the CPU count (deadpool's own default was 2 on a 1-vCPU node),
//!   and every timeout is set.
//! - **I1481** (v59.1.2) — a starved pool is a TYPED error inside its wait,
//!   never a hang: the store, federation, audit and secrets arms each carry
//!   it as `PoolExhausted`.
//! - **I1482** (v59.1.2) — the doors the field wedge named hold one client
//!   and reach for a second no more: each finishes on a one-connection pool
//!   whose checkout gives up after [`SHORT_WAIT`] (a nested checkout answers
//!   `PoolExhausted`, so a regression fails fast instead of at the bound).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::federation::delegation_cycle_invariants::bodies as dc;
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

/// The content hash the index must hold for `(kind, key)`: the stored bytes,
/// read the way the point read reads them.
async fn indexed(b: &PostgresBackend, kind: &str, key: &str) -> bool {
    let want = crate::federation::wire_index::entry_as_stored(b, kind, key)
        .await
        .unwrap()
        .expect("the record is stored");
    b.list_wire_hashes_since(kind, None, 100_000)
        .await
        .unwrap()
        .contains(&want)
}

/// **I601** — see the module doc.
#[tokio::test(flavor = "multi_thread")]
async fn i601_the_wire_index_reindex_completes_on_one_connection() {
    let Some(b) = one_connection_backend("i601").await else {
        return;
    };
    let tag = suffix();
    let k = format!("i601-k-{tag}");
    // v58.0.0 (CIRISPersist#991) — a key's record is its `key:record:v1` row,
    // indexed on the Attestation kind after the door commits.
    within_bound(
        "I601 key registration",
        b.put_public_key(crate::federation::SignedKeyRecord {
            record: crate::federation::key_plane_invariants::bodies::pop_record(&k),
        }),
    )
    .await
    .expect("I601 the key registers");
    let row_id = crate::federation::key_plane_invariants::bodies::key_row(&b, &k)
        .await
        .expect("I601 the key is a key:record:v1 row")
        .attestation_id;
    assert!(
        indexed(
            &b,
            "Attestation",
            &crate::federation::wire_index::record_key(&[("attestation_id", &row_id)])
        )
        .await,
        "I601 the key row's re-index ran and stored its stored-bytes hash"
    );
    // A self-edge is not cycle-gated (the root charter's shape), so this put
    // reaches the re-index without the delegation lock: I601 measures the
    // re-index alone.
    let id = within_bound(
        "I601 attestation put",
        ts::put_delegates_to(&b as &dyn FederationDirectory, &k, &k, None),
    )
    .await
    .expect("I601 the self-edge admits");
    assert!(
        indexed(
            &b,
            "Attestation",
            &crate::federation::wire_index::record_key(&[("attestation_id", &id)])
        )
        .await,
        "I601 the attestation's re-index ran and stored its stored-bytes hash"
    );
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
    // The re-check still runs under the lock: the closing edge is refused.
    match within_bound(
        "I602 the cycle-closing put",
        ts::put_delegates_to(d, &c, &a, None),
    )
    .await
    {
        Err(Error::DelegationCycle { .. }) => {}
        other => panic!("I602 c → a closes a cycle and must be refused: {other:?}"),
    }
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
    use crate::store::postgres::{
        pool_config, POOL_CREATE_TIMEOUT, POOL_MAX_SIZE_FLOOR, POOL_RECYCLE_TIMEOUT,
    };
    let wait = std::time::Duration::from_secs(7);
    for cpus in [0, 1, 2, 7, 8] {
        assert_eq!(
            pool_config(None, cpus, wait).max_size,
            POOL_MAX_SIZE_FLOOR,
            "I1480 {cpus} CPU(s): the floor, not deadpool's 2 x CPUs"
        );
    }
    assert_eq!(
        pool_config(None, 12, wait).max_size,
        24,
        "I1480 above the floor the CPU-derived size stands"
    );
    assert_eq!(
        POOL_MAX_SIZE_FLOOR, 16,
        "I1480 the floor the field fix chose"
    );
    assert_eq!(
        pool_config(Some(1), 1, wait).max_size,
        1,
        "I1480 an explicit size is the caller's"
    );
    let t = pool_config(None, 1, wait).timeouts;
    assert_eq!(t.wait, Some(wait), "I1480 checkout waits a bounded time");
    assert_eq!(t.create, Some(POOL_CREATE_TIMEOUT));
    assert_eq!(t.recycle, Some(POOL_RECYCLE_TIMEOUT));
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
    let c = crate::store::postgres::checkout(b.pool())
        .await
        .expect_err("I1481 checkout");
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
    ts::register_hybrid_key(d, &identity).await;
    ts::register_hybrid_key(d, &occ).await;
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
        b.put_identity_occurrence_local(row),
    )
    .await
    .expect("I1482 the local occurrence lands and projects its route");
    assert_eq!(
        b.list_transport_destinations_for(&occ).await.unwrap().len(),
        1,
        "I1482 the route projection ran"
    );
}

/// **I1482** — the wire-index point read reloads the record through the
/// directory after reading its key.
#[tokio::test(flavor = "multi_thread")]
async fn i1482_the_wire_index_point_read_completes_on_one_connection() {
    let Some(b) = starved_backend("i1482-wire", 1).await else {
        return;
    };
    let k = format!("i1482-k-{}", suffix());
    within_bound(
        "I1482 key registration",
        b.put_public_key(crate::federation::SignedKeyRecord {
            record: crate::federation::key_plane_invariants::bodies::pop_record(&k),
        }),
    )
    .await
    .expect("I1482 the key registers");
    let row_id = crate::federation::key_plane_invariants::bodies::key_row(&b, &k)
        .await
        .expect("I1482 the key row")
        .attestation_id;
    let key = crate::federation::wire_index::record_key(&[("attestation_id", &row_id)]);
    let hash = crate::federation::wire_index::entry_as_stored(&b, "Attestation", &key)
        .await
        .unwrap()
        .expect("I1482 stored");
    let bytes = within_bound(
        "I1482 lookup_signed_record_by_content_hash",
        b.lookup_signed_record_by_content_hash("Attestation", &hash),
    )
    .await
    .expect("I1482 the point read finishes");
    assert!(bytes.is_some(), "I1482 the indexed record reloads");
}
