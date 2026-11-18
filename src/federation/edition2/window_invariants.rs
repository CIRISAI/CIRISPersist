//! v62.0.0 (kernel pass 2, K1) — **I2820: a record's window is half-open,
//! and a window that covers nothing is refused**, on sqlite and postgres.
//!
//! CC ruling: a record covers `t` when `asserted_at <= t < valid_until`,
//! half-open everywhere ([`crate::kernel::key_end::within_record`]).
//!
//! - A node key held by a record over `[1_000, 10_000)`: a statement it
//!   signs at `valid_until - 1` is not waiting on its key; at `valid_until`
//!   and `valid_until + 1` it waits (`federation_attester_key_unknown`,
//!   retryable).
//! - A `key:record` stating `valid_until == asserted_at`, or before it, is
//!   refused `valid_until_not_after_asserted_at` at the door, and nothing is
//!   held.

use super::door_invariants::fixture::*;
use super::ingest::{put_statement, INGEST_TIER};
use crate::federation::{malformed_row, Error, FederationDirectory};

fn reason(e: &Error) -> String {
    match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    }
}

/// A statement `k` signs at `at`.
fn signed_at(k: &ciris_crypto::composite::CompositeSigningKey, at: u64) -> Vec<u8> {
    row_with_refs(k, at, map(vec![("target", ref2(&[0xaa; 32]))]))
}

const WAITS: &str = "federation_attester_key_unknown";

/// **I2820** — see the module doc.
pub(crate) async fn body(d: &dyn FederationDirectory) {
    // The refusal: a window that covers no instant.
    let z = key(72);
    for (why, until) in [("equal", 5_000), ("before", 4_999)] {
        let e = put_statement(
            d,
            &key_record(&z, &["node"], 5_000, Some(until)),
            None,
            INGEST_TIER,
        )
        .await
        .expect_err("I2820: an empty window is refused");
        assert_eq!(
            reason(&e),
            malformed_row::VALID_UNTIL_NOT_AFTER_ASSERTED_AT,
            "I2820 ({why}): {e:?}"
        );
    }
    assert!(
        d.edition2_statements_about("key:record", &iref(&z))
            .await
            .unwrap()
            .is_empty(),
        "I2820: nothing held"
    );
    // One millisecond of window is a window.
    put_statement(
        d,
        &key_record(&z, &["node"], 5_000, Some(5_001)),
        None,
        INGEST_TIER,
    )
    .await
    .unwrap_or_else(|e| panic!("I2820: [5_000, 5_001) is admitted: {e:?}"));

    // The boundary.
    let k = key(70);
    put_statement(
        d,
        &key_record(&k, &["node"], 1_000, Some(10_000)),
        None,
        INGEST_TIER,
    )
    .await
    .unwrap_or_else(|e| panic!("I2820: the record: {e:?}"));
    for at in [10_000, 10_001] {
        let e = put_statement(d, &signed_at(&k, at), None, INGEST_TIER)
            .await
            .expect_err("I2820: no record covers the instant");
        assert_eq!(
            e.kind(),
            WAITS,
            "I2820 at {at}: retryable, waits on the key: {e:?}"
        );
    }
    // Last: the statement is a key-plane row of `k`'s own, so it is judged
    // once nothing after it reads `k`.
    if let Err(e) = put_statement(d, &signed_at(&k, 9_999), None, INGEST_TIER).await {
        assert_ne!(
            e.kind(),
            WAITS,
            "I2820 at 9_999: the record covers it: {e:?}"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2820_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2820_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        eprintln!("i2820 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
    eprintln!("i2820 postgres: RAN");
}
