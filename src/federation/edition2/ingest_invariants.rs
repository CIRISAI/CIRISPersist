//! **I1906** (the statement store) and **I1909** (one rule set, two codecs),
//! on sqlite and postgres.
//!
//! - I1906:
//!   - a `key:record` statement is kept in `ceg_statements` under its row id,
//!     idempotently, and is read back as received by
//!     `edition2_statements_about`;
//!   - a row's names land in `ceg_row_names`;
//!   - the columns are the shape the E2b baseline creates.
//! - I1909:
//!   - an edition-2 row from a live edition-2 key passes the SAME attestation
//!     gates as the JSON door and is stored under its node-computed row id
//!     (`attestation_id` = `persist_row_hash` = the row id);
//!   - a JSON object at the statement entry is `earlier_form_object`;
//!   - an offered id that is not the computed one is `row_id_mismatch`;
//!   - a row from a key with no edition-2 record waits (retryable);
//!   - a mapped row whose envelope was altered after mapping, put straight
//!     through the JSON door, is refused `typed_diverges_from_envelope`;
//!   - a mapped row naming a different id is refused `row_id_mismatch`.

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::sign_row_statement;

use super::door::admit_row;
use super::door_invariants::fixture::*;
use super::ingest::{attestation_of, put_statement, StatementOutcome, INGEST_TIER};
use super::liveness::HeldKeys;
use crate::federation::types::SignedAttestation;
use crate::federation::{malformed_row, Error, FederationDirectory};

/// An authored score row (Verify's vector family), naming `target`.
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
        (
            "refs",
            map(vec![(
                "also",
                map(vec![("cites", Value::Array(vec![ref2(&[0x31; 32])]))]),
            )]),
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

fn reason(e: &Error) -> String {
    match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    }
}

/// TODO(baseline-merge): remove. The signer FKs the E2b baseline does not carry (postgres).
pub(crate) const EDITION2_SIGNER_FKS_DROPPED_PG: &str = "\
    ALTER TABLE cirislens.federation_attestations \
      DROP CONSTRAINT IF EXISTS federation_attestations_attesting_key_id_fkey; \
    ALTER TABLE cirislens.federation_attestations \
      DROP CONSTRAINT IF EXISTS federation_attestations_scrub_key_id_fkey;";

pub(crate) async fn body(d: &dyn FederationDirectory) {
    let k = key(60);
    let record = key_record(&k, &["user"], 0, None);
    // I1906: the key plane.
    let out = put_statement(d, &record, None, INGEST_TIER).await.unwrap();
    let StatementOutcome::KeyPlane { row_id, new: true } = out else {
        panic!("I1906: {out:?}");
    };
    assert_eq!(
        put_statement(d, &record, None, INGEST_TIER).await.unwrap(),
        StatementOutcome::KeyPlane { row_id, new: false },
        "I1906: idempotent"
    );
    let held = d
        .edition2_statements_about("key:record", &iref(&k))
        .await
        .unwrap();
    assert_eq!(held, vec![record.clone()], "I1906: read back as received");

    // I1909: a row through the attestation gates.
    let st = score_row(&k, 5_000);
    let out = put_statement(d, &st, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I1909: {e:?}"));
    let StatementOutcome::Row { row_id, new: true } = out else {
        panic!("I1909: {out:?}");
    };
    let stored = d
        .get_attestation(&row_id.hex())
        .await
        .unwrap()
        .expect("I1909: stored under its row id");
    assert_eq!(
        stored.persist_row_hash,
        row_id.hex(),
        "I1909: persist_row_hash is the row id"
    );
    assert_eq!(stored.attesting_key_id, iref(&k), "I1909");

    // Refusals.
    let e = put_statement(d, br#"{"attestation":{}}"#, None, INGEST_TIER)
        .await
        .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_EARLIER_FORM_OBJECT,
        "I1909 json"
    );
    let mut wrong = row_id.0;
    wrong[3] ^= 0x10;
    let e = put_statement(d, &st, Some(&wrong), INGEST_TIER)
        .await
        .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_ROW_ID_MISMATCH,
        "I1909 offered id"
    );
    let stranger = key(61);
    let e = put_statement(d, &score_row(&stranger, 5_000), None, INGEST_TIER)
        .await
        .unwrap_err();
    assert_eq!(
        e.kind(),
        "federation_attester_key_unknown",
        "I1909 no record: waits"
    );

    // A mapped row altered after mapping, through the JSON door.
    let mut keys = HeldKeys::new();
    keys.insert_record(record.clone());
    let st2 = score_row(&k, 6_000);
    let admitted = admit_row(&st2, &keys, None, SelectContext::default()).unwrap();
    let mut forged = attestation_of(&admitted, INGEST_TIER).unwrap();
    forged.attestation_envelope["dimension"] =
        serde_json::json!("evidence:safety_battery:capture:a:c:v1");
    forged.original_content_hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        crate::verify::canonical::ceg_produce_canonicalize(&forged.attestation_envelope).unwrap(),
    ));
    let e = d
        .put_attestation(SignedAttestation {
            attestation: forged,
        })
        .await
        .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::TYPED_DIVERGES_FROM_ENVELOPE,
        "I1909 forged"
    );
    let mut renamed = attestation_of(&admitted, INGEST_TIER).unwrap();
    renamed.attestation_id = hex::encode([7u8; 32]);
    renamed.persist_row_hash = renamed.attestation_id.clone();
    renamed.attestation_envelope["row"]["attestation_id"] =
        serde_json::json!(renamed.attestation_id);
    renamed.original_content_hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        crate::verify::canonical::ceg_produce_canonicalize(&renamed.attestation_envelope).unwrap(),
    ));
    let e = d
        .put_attestation(SignedAttestation {
            attestation: renamed,
        })
        .await
        .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_ROW_ID_MISMATCH,
        "I1909 renamed"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i1906_i1909_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    {
        let c = b.conn_handle();
        let c = c.lock();
        c.execute_batch(super::store::SQLITE_DDL).unwrap();
        // TODO(baseline-merge): remove. The E2b baseline drops the earlier store's signer FK to
        // `federation_keys`; an edition-2 signer lives in `ceg_statements`.
        c.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    }
    Box::pin(body(&b)).await;
    // The names landed.
    let k = key(60);
    let st = score_row(&k, 5_000);
    let mut keys = HeldKeys::new();
    keys.insert_record(key_record(&k, &["user"], 0, None));
    let row = admit_row(&st, &keys, None, SelectContext::default()).unwrap();
    let conn = b.conn_handle();
    let c = conn.lock();
    let naming =
        super::store::rows_naming_sqlite(&c, &super::names::RowId([0x31; 32]), "also:cites")
            .unwrap();
    assert_eq!(naming, vec![row.row_id], "I1906: ceg_row_names");
    let cols: Vec<String> = c
        .prepare("SELECT name FROM pragma_table_info('ceg_statements') ORDER BY cid")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(cols, super::store::STATEMENT_COLUMNS, "I1906: the columns");
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i1906_i1909_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    let c = b.pool().get().await.unwrap();
    c.batch_execute(super::store::POSTGRES_DDL).await.unwrap();
    // TODO(baseline-merge): remove. The E2b baseline drops the earlier store's signer FKs to
    // `federation_keys`; an edition-2 signer lives in `ceg_statements`.
    c.batch_execute(EDITION2_SIGNER_FKS_DROPPED_PG)
        .await
        .unwrap();
    Box::pin(body(&b)).await;
    let naming =
        super::store::rows_naming_postgres(&c, &super::names::RowId([0x31; 32]), "also:cites")
            .await
            .unwrap();
    assert_eq!(naming.len(), 1, "I1906: ceg_row_names");
}
