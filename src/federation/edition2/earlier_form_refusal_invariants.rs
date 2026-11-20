//! **I2100** (v62.0.0, JSON-cut slice A): the one shared earlier-form
//! refusal, on sqlite and postgres.
//!
//! - v62.0.0 (slice F): [`EARLIER_FORM_DOORS_SHUT`] is `true`, so
//!   [`refuse_earlier_form`] refuses `earlier_form_object` by name, and the
//!   attestation door refuses a JSON row before it parses or verifies
//!   anything. (The switch-off leg and the test-only forcing scope went with
//!   the flip.)
//! - A row that carries its edition-2 statement (`ceg_statement`, the
//!   edition-2 door's mapping) is never an earlier-form object: it passes the
//!   refusal and reaches the gates.

use super::door::{earlier_form_doors_shut, refuse_earlier_form, EARLIER_FORM_DOORS_SHUT};
use crate::federation::{malformed_row, Error};
#[cfg(any(feature = "sqlite", feature = "postgres"))]
use {
    super::door::{admit_row, refuse_earlier_form_row},
    super::door_invariants::fixture::*,
    super::ingest::{attestation_of, put_statement, INGEST_TIER, STATEMENT_MEMBER},
    super::liveness::HeldKeys,
    crate::federation::types::SignedAttestation,
    crate::federation::FederationDirectory,
    ciris_verify_core::cde::Value,
    ciris_verify_core::edition2::family::SelectContext,
    ciris_verify_core::edition2::sign_row_statement,
};

#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn score_row(k: &ciris_crypto::composite::CompositeSigningKey, at: u64) -> Vec<u8> {
    let payload = map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        (
            "dimension",
            Value::Text("evidence:safety_battery:capture:a:b:v1".into()),
        ),
    ]);
    sign_row_statement(
        k,
        &iref(k),
        &iref(k),
        "scores",
        "evidence:.suite:.kind:.cell:.prefix",
        &payload,
        vec![],
    )
    .unwrap()
}

fn reason(e: &Error) -> &'static str {
    match e {
        Error::MalformedRow { reason, .. } => reason,
        other => other.kind(),
    }
}

// v62.0.0 (slice F): `i2100_the_switch_is_off_until_slice_f` is deleted —
// F flipped the switch; I2870 (doors_shut_invariants.rs) asserts it is on.

#[test]
fn i2100_the_switch_refuses_by_name() {
    assert!(
        EARLIER_FORM_DOORS_SHUT && earlier_form_doors_shut(),
        "I2100: the doors are shut"
    );
    let e = refuse_earlier_form("key_record").unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_EARLIER_FORM_OBJECT,
        "I2100"
    );
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) async fn body(d: &dyn FederationDirectory) {
    let k = key(70);
    let record = key_record(&k, &["user"], 0, None);
    put_statement(d, &record, None, INGEST_TIER).await.unwrap();
    let mut keys = HeldKeys::new();
    keys.insert_record(record);
    let st = score_row(&k, 5_000);
    let mapped = attestation_of(
        &admit_row(&st, &keys, None, SelectContext::default()).unwrap(),
        INGEST_TIER,
    )
    .unwrap();
    // The same row with its statement stripped: an earlier-form JSON row.
    let mut json_row = mapped.clone();
    json_row
        .attestation_envelope
        .as_object_mut()
        .unwrap()
        .remove(STATEMENT_MEMBER);

    refuse_earlier_form_row("attestation", &mapped).expect("I2100: the mapping passes");
    let e = refuse_earlier_form_row("attestation", &json_row).unwrap_err();
    assert_eq!(reason(&e), malformed_row::EDITION2_EARLIER_FORM_OBJECT);
    let e = d
        .put_attestation(SignedAttestation {
            attestation: json_row.clone(),
        })
        .await
        .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_EARLIER_FORM_OBJECT,
        "I2100: the attestation door refuses the JSON row by name"
    );
    // The edition-2 statement still lands, through the same door.
    put_statement(d, &st, None, INGEST_TIER)
        .await
        .expect("I2100: the edition-2 door stays open");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2100_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2100_postgres() {
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
