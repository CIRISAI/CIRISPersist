//! v62.0.0 (PRE4-retire; CIRISConstitution v1.0-rc22-pre4,
//! `manifests/scitt_names.tsv`) — **I6403: a row of each of the five retired
//! families is refused BY NAME at the statement door**
//! (`federation_malformed_row` / `family_retired`), on sqlite and postgres:
//! `transparency_log:cosigned:{tree_size}`, `transparency_log:inclusion`,
//! `transparency_log:consistency`, `lineage_witness:{stage}`,
//! `trust:blessing`, and (PRE4-cosign) `cosign:{state}`, both leaves. The
//! refusal is a pure gate, before any key is asked or any row is written;
//! the witness reads the statement store and finds nothing kept.
//!
//! APPLIES ONLY WITH PIN-pre4 (the re-vendor that drops the five from the
//! vendored registry); the door refuses them before that too.

use ciris_verify_core::cde::Value;

use super::fixture_switch as e2;
use crate::federation::{Error, FederationDirectory};

const SIGNER: &str = "pre4-retired-signer";

/// The five, each as (registry prefix, a dimension under it).
const RETIRED: [(&str, &str); 5] = [
    (
        "transparency_log:cosigned:{tree_size}",
        "transparency_log:cosigned:42:v1",
    ),
    (
        "transparency_log:inclusion",
        "transparency_log:inclusion:v1",
    ),
    (
        "transparency_log:consistency",
        "transparency_log:consistency:v1",
    ),
    ("lineage_witness:{stage}", "lineage_witness:propose:v1"),
    ("trust:blessing", "trust:blessing:v1"),
];

/// A minimal payload, keys in the deterministic order (shorter first).
fn payload(dimension: &str) -> Value {
    Value::Map(vec![
        (
            Value::Text("author".to_owned()),
            Value::Text(e2::kid(SIGNER)),
        ),
        (
            Value::Text("dimension".to_owned()),
            Value::Text(dimension.to_owned()),
        ),
        (
            Value::Text("asserted_at".to_owned()),
            Value::Uint(1_700_000_000_000),
        ),
    ])
}

/// Offer `st`: refused `family_retired`, and nothing of it kept.
async fn refused_by_name(d: &dyn FederationDirectory, st: &[u8], what: &str) {
    match e2::put_statement(d, st).await {
        Err(Error::MalformedRow { reason, .. }) => assert_eq!(
            reason,
            crate::federation::malformed_row::FAMILY_RETIRED,
            "I6403 {what}"
        ),
        other => panic!("I6403 {what} must be refused family_retired, got {other:?}"),
    }
    let id = super::names::RowId::of_statement(st).expect("I6403: a row statement");
    assert!(
        d.edition2_voices(&id).await.unwrap().is_empty(),
        "I6403 {what}: nothing kept"
    );
}

async fn retired_families_are_refused_by_name_body(d: &dyn FederationDirectory) {
    for (prefix, dimension) in RETIRED {
        let st = e2::typed_statement(SIGNER, None, SIGNER, prefix, &payload(dimension));
        refused_by_name(d, &st, prefix).await;
    }
    // v62.0.0 (PRE4-cosign; CC v1.0-rc22-pre4, the sixth retirement) — a
    // peer-fed `cosign:pending:v1` / `cosign:signature:v1` statement is refused
    // by its family before anything else is read, so whether its event is held
    // does not matter (the held case at the real door is I3165, I3834).
    let event_id = super::names::RowId([9; 32]);
    for state in ["pending", "signature"] {
        let st = e2::retired_cosign_statement(SIGNER, state, SIGNER, &event_id, 1_700_000_000_500);
        refused_by_name(d, &st, &format!("cosign:{state}:v1")).await;
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6403_retired_families_are_refused_by_name_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(retired_families_are_refused_by_name_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6403_retired_families_are_refused_by_name_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(retired_families_are_refused_by_name_body(&b)).await;
}
