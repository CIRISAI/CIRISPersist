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

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::federation::delegation_cycle_invariants::bodies as dc;
use crate::federation::tier_ingest::test_support as ts;
use crate::federation::{Error, FederationDirectory};
use crate::store::postgres::PostgresBackend;
use crate::store::Backend as _;

/// Long enough for every door on a cold one-connection pool, short enough
/// that a hang reports instead of eating the lane's budget.
const BOUND: std::time::Duration = std::time::Duration::from_secs(60);

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
    within_bound("I601 key registration", ts::register_hybrid_key(&b, &k)).await;
    assert!(
        indexed(
            &b,
            "Key",
            &crate::federation::wire_index::record_key(&[("key_id", &k)])
        )
        .await,
        "I601 the key's re-index ran and stored its stored-bytes hash"
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
