//! **I3035–I3036** (wave O1; C1's atomic genesis import, "a row is the
//! same row inside a bundle and alone"): the edition-2 occurrence write as a
//! transaction-level helper, on sqlite and postgres.
//!
//! - I3035: the helper writes nothing of its own: inside a transaction the
//!   caller rolls back (a fault before commit), no occurrence row and no
//!   history row is left; inside one it commits, both are there.
//! - I3036: a genesis bundle's placed seats land in the occurrence table
//!   with the bundle (C1's `put_edition2_genesis` calls the helper inside
//!   its one transaction; C2's ceremony).

use super::door_invariants::fixture::{iref, key, key_record};
use super::ingest::{put_statement, INGEST_TIER};
use super::names::RowId;
use super::occurrence::OccurrenceBind;
use crate::federation::occurrence_admit::{plan_edition2_occurrence, PlannedOccurrence};
use crate::federation::types::IdentityOccurrence;
use crate::federation::FederationDirectory;

/// A self-pair bind of `seed`'s key (a seat's shape), planned.
async fn planned_self_pair(d: &dyn FederationDirectory, seed: u8) -> (String, PlannedOccurrence) {
    let k = key(seed);
    Box::pin(put_statement(
        d,
        &key_record(&k, &["user"], 0, None),
        None,
        INGEST_TIER,
    ))
    .await
    .unwrap();
    let r = iref(&k);
    let bind = OccurrenceBind {
        occurrence: IdentityOccurrence {
            identity_key_id: r.clone(),
            occurrence_key_id: r.clone(),
            device_class: "server".to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(10_000).unwrap(),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        },
        author_key_id: r.clone(),
        row_id: RowId([seed; 32]),
        statements: Vec::new(),
    };
    let (planned, route) = plan_edition2_occurrence(bind).unwrap();
    assert!(route.is_none(), "no transport, no route");
    (r, planned)
}

async fn held(d: &dyn FederationDirectory, r: &str) -> (usize, usize) {
    let rows = d.list_identity_occurrences_for(r).await.unwrap().len();
    let hist = d
        .list_identity_occurrence_history_by_occurrence(r)
        .await
        .unwrap()
        .len();
    (rows, hist)
}

/// I3036 on one backend: every placed seat is bound as its own occurrence.
async fn genesis_seats(d: &dyn FederationDirectory) {
    use super::fixture_genesis::{bundle_v2, install_v2};
    install_v2(d).await.unwrap();
    for seat in &bundle_v2().seats {
        let bound = d
            .list_identity_occurrences_for(&seat.identity_ref)
            .await
            .unwrap();
        assert!(
            bound
                .iter()
                .any(|o| o.occurrence_key_id == seat.identity_ref),
            "I3036: seat {} is in the occurrence table",
            seat.identity_ref
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3035_i3036_sqlite() {
    use crate::store::sqlite::sqlite_store_edition2_occurrence;
    use crate::store::sqlite_conn_model::write_tx;
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    let (r, planned) = Box::pin(planned_self_pair(&b, 81)).await;
    {
        let conn = b.conn_handle();
        let mut c = conn.lock();
        let tx = write_tx(&mut c).unwrap();
        assert!(sqlite_store_edition2_occurrence(&tx, &planned).unwrap());
        // A fault before commit: the caller's transaction rolls back.
        drop(tx);
    }
    assert_eq!(
        held(&b, &r).await,
        (0, 0),
        "I3035: nothing survives a rollback"
    );
    {
        let conn = b.conn_handle();
        let mut c = conn.lock();
        let tx = write_tx(&mut c).unwrap();
        assert!(sqlite_store_edition2_occurrence(&tx, &planned).unwrap());
        tx.commit().unwrap();
    }
    assert_eq!(
        held(&b, &r).await,
        (1, 1),
        "I3035: the caller's commit keeps both"
    );
    Box::pin(genesis_seats(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3035_i3036_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    let (r, planned) = Box::pin(planned_self_pair(&b, 81)).await;
    {
        let mut c = b.checkout().await.unwrap();
        let tx = c.transaction().await.unwrap();
        assert!(b.pg_store_edition2_occurrence(&tx, &planned).await.unwrap());
        // A fault before commit: the caller's transaction rolls back.
        drop(tx);
    }
    assert_eq!(
        held(&b, &r).await,
        (0, 0),
        "I3035: nothing survives a rollback"
    );
    {
        let mut c = b.checkout().await.unwrap();
        let tx = c.transaction().await.unwrap();
        assert!(b.pg_store_edition2_occurrence(&tx, &planned).await.unwrap());
        tx.commit().await.unwrap();
    }
    assert_eq!(
        held(&b, &r).await,
        (1, 1),
        "I3035: the caller's commit keeps both"
    );
    Box::pin(genesis_seats(&b)).await;
}
