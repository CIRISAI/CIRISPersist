//! **I2105** (v62.0.0, JSON-cut slice A): a composer's target, on sqlite and
//! postgres.
//!
//! - A `withdraws` naming a held row of its own family is admitted, and the
//!   mapped row's `references_attestation_id` is the target's node-computed
//!   row id (from `refs.target`, never a peer string).
//! - A composer whose family is not its target's is
//!   `composer_family_mismatch`.
//! - A composer naming a row this node does not hold waits: the retryable
//!   `federation_withdraws_target_unheld`.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;

use super::door_invariants::fixture::*;
use super::names::RowId;

const FAMILY: &str = "evidence:.suite:.kind:.cell:.prefix";
const DIMENSION: &str = "evidence:safety_battery:capture:a:b:v1";

fn score(k: &CompositeSigningKey, at: u64) -> Vec<u8> {
    let m = map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        ("dimension", Value::Text(DIMENSION.into())),
    ]);
    sign_row_statement(k, &iref(k), &iref(k), "scores", FAMILY, &m, vec![]).unwrap()
}

fn withdraws(k: &CompositeSigningKey, family: &str, target: &RowId, at: u64) -> Vec<u8> {
    let mut m = vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("refs", map(vec![("target", ref2(&target.0))])),
    ];
    // A dimension is carried only under the family that binds it.
    if family == FAMILY {
        m.push(("dimension", Value::Text(DIMENSION.into())));
    }
    sign_row_statement(k, &iref(k), &iref(k), "withdraws", family, &map(m), vec![]).unwrap()
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) async fn body(d: &dyn crate::federation::FederationDirectory) {
    use super::ingest::{put_statement, StatementOutcome, INGEST_TIER, REFERENCES_MEMBER};
    use crate::federation::{malformed_row, Error};
    let reason = |e: &Error| match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    };
    let k = key(130);
    put_statement(d, &key_record(&k, &["user"], 0, None), None, INGEST_TIER)
        .await
        .unwrap();
    let target = score(&k, 5_000);
    let StatementOutcome::Row { row_id: t, .. } =
        put_statement(d, &target, None, INGEST_TIER).await.unwrap()
    else {
        panic!("I2105 target");
    };
    // Unheld target: waits.
    let e = put_statement(
        d,
        &withdraws(&k, FAMILY, &RowId([0x77; 32]), 6_000),
        None,
        INGEST_TIER,
    )
    .await
    .unwrap_err();
    assert_eq!(
        e.kind(),
        "federation_withdraws_target_unheld",
        "I2105 unheld"
    );
    // Another family than the target's.
    let e = put_statement(
        d,
        &withdraws(&k, "key:revocation", &t, 6_000),
        None,
        INGEST_TIER,
    )
    .await
    .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::COMPOSER_FAMILY_MISMATCH,
        "I2105 mismatch"
    );
    // The target's family: admitted, naming the target by its row id.
    let StatementOutcome::Row { row_id: w, .. } =
        put_statement(d, &withdraws(&k, FAMILY, &t, 6_000), None, INGEST_TIER)
            .await
            .unwrap_or_else(|e| panic!("I2105 admitted: {e:?}"))
    else {
        panic!("I2105 row");
    };
    let stored = d.get_attestation(&w.hex()).await.unwrap().unwrap();
    assert_eq!(
        stored.attestation_envelope[REFERENCES_MEMBER],
        serde_json::json!(t.hex()),
        "I2105 references_attestation_id"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2105_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2105_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}
