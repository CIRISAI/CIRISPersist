//! v62.0.0 (v62 P8) — **I3530: the external holding claim is an edition-2
//! statement a SECOND node admits.** sqlite and postgres.
//!
//! - **I3530** — the door Python's `put_blob` calls
//!   (`BlobStorage::put_blob`): node A stores a blob under a
//!   holder's `custody:ack` statement signed outside persist (no
//!   `PutBlobAttestation`, nothing signed over a JCS image). A keeps the
//!   statement and lists the holder; node B, holding the holder's key,
//!   admits the same statement through the statement door, under the same
//!   row id, and lists the same holder.
//!
//! The occurrence producer's witness (I3532) is in cut B's
//! `edition2::crossing_producer_invariants`: it needs an Engine.

use crate::federation::edition2::fixture_switch as e2;
use crate::federation::edition2::ingest::{put_statement, INGEST_TIER};
use crate::federation::{BlobStorage, FederationDirectory};

async fn kept<D: FederationDirectory + ?Sized>(d: &D, st: &[u8]) -> bool {
    let rid = crate::federation::edition2::names::RowId::of_statement(st).expect("a row statement");
    !d.edition2_voices(&rid).await.unwrap().is_empty()
}

/// I3530.
async fn external_claim_body<B>(a: &B, b: &B, tag: &str)
where
    B: FederationDirectory + BlobStorage + Sync,
{
    use sha2::Digest as _;
    let holder = format!("p8-holder-{tag}");
    let hi = e2::put_key(a, &holder, &["user"]).await;
    e2::put_key(b, &holder, &["user"]).await;
    let bytes = format!("p8 external claim {tag}").into_bytes();
    let sha: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    let claim = e2::custody_statement(
        &holder,
        &sha,
        Some(bytes.len() as u64),
        "federation",
        None,
        e2::ms(crate::host::clock::now()),
    );
    a.put_blob(
        &sha,
        crate::federation::BlobBody::Inline(bytes.clone()),
        Some("text/plain"),
        &claim,
    )
    .await
    .expect("I3530: A stores the bytes under the edition-2 claim");
    assert!(kept(a, &claim).await, "I3530: A keeps the claim statement");
    let at_a = crate::federation::holding_claim::list_holders_of(a, &sha)
        .await
        .unwrap();
    assert!(at_a.contains(&hi), "I3530: A lists the holder: {at_a:?}");

    // B, holding the holder's key, admits the same bytes.
    put_statement(b, &claim, None, INGEST_TIER)
        .await
        .expect("I3530: B admits the claim statement");
    assert!(kept(b, &claim).await, "I3530: B keeps the claim statement");
    let at_b = crate::federation::holding_claim::list_holders_of(b, &sha)
        .await
        .unwrap();
    assert!(at_b.contains(&hi), "I3530: B lists the holder: {at_b:?}");
}

fn tag() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
}

#[cfg(feature = "sqlite")]
async fn sqlite() -> crate::store::sqlite::SqliteBackend {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b
}

#[cfg(feature = "postgres")]
async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
    use crate::store::Backend as _;
    let dsn = crate::test_pg::isolated_dsn()?;
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
}

#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn i3530_external_claim_sqlite() {
    let (a, b) = (sqlite().await, sqlite().await);
    Box::pin(external_claim_body(&a, &b, &tag())).await;
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn i3530_external_claim_postgres() {
    let (Some(a), Some(b)) = (postgres().await, postgres().await) else {
        eprintln!("i3530 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
        return;
    };
    Box::pin(external_claim_body(&a, &b, &tag())).await;
    eprintln!("i3530 postgres: RAN");
}
