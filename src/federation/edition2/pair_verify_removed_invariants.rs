//! v62.0.0 (BH-fix1; RULINGS "composite signatures only") — **the quorum
//! counts that verified a SEPARATE Ed25519 + ML-DSA-65 pair** (Verify's
//! `ThresholdSignature`, `verify_threshold_signatures`) now count the
//! edition-2 door's vouched voices only: each voice is ONE composite
//! statement, verified when it arrived.
//!
//! - **I2120** deleted in v62.0.0 (RL-fix7): the accord's standing-majority
//!   count it witnessed (`tier_ingest::standing_majority_signed_by`, read by
//!   the accord head version and roster change) is deleted with those doors;
//!   the accord is the genesis bundle in force.
//! - **I2121** deleted in v62.0.0 (RESIGN-3; CC 3.1.3.2): the self-leave
//!   (`family_dissolution::verify_self_leave_signature`, CIRISPersist#956) it
//!   witnessed is retired with its arm. A roster version is the group's
//!   counted row; a member's own leaving is the `membership:resignation` leaf
//!   (I283 rewritten, I6802).
//! - **I2122** (sqlite AND postgres) — a skill import is an edition-2 ROW:
//!   one composite `provenance:skill_import:{source}` statement lands through
//!   the statement door, and the earlier manifest's refusal names
//!   `earlier_form_object` (`door::skill_import_manifest_refusal`, the
//!   refusal `verify_skill_import_manifest_b64` raises; I2123 holds the verb).

use crate::federation::{malformed_row, Error, FederationDirectory};

/// A composite `provenance:skill_import:{source}` row by `k` at `at` ms: the
/// source `registry:ciris-registry-us` (a multi-segment value), version `v1`.
fn skill_import_row(k: &ciris_crypto::composite::CompositeSigningKey, at: u64) -> Vec<u8> {
    use super::door_invariants::fixture::{iref, map};
    use ciris_verify_core::cde::Value;
    let payload = map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("score", Value::Uint(1_000_000)),
        ("confidence", Value::Uint(1_000_000)),
        (
            "dimension",
            Value::Text("provenance:skill_import:registry:ciris-registry-us:v1".into()),
        ),
    ]);
    ciris_verify_core::edition2::sign_row_statement(
        k,
        &iref(k),
        &iref(k),
        "scores",
        &ciris_verify_core::namespace_match::family_id("provenance:skill_import:{source}"),
        &payload,
        vec![],
    )
    .expect("I2122: sign")
}

async fn skill_import(d: &dyn FederationDirectory) {
    use super::door_invariants::fixture::{key, key_record};
    use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
    let k = key(73);
    put_statement(d, &key_record(&k, &["user"], 0, None), None, INGEST_TIER)
        .await
        .expect("I2122: the signer's edition-2 key:record lands");
    let out = put_statement(d, &skill_import_row(&k, 6_000), None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| {
            panic!("I2122: a composite provenance:skill_import row is admitted: {e:?}")
        });
    assert!(
        matches!(out, StatementOutcome::Row { new: true, .. }),
        "I2122: the skill import lands as a row: {out:?}"
    );
    match super::door::skill_import_manifest_refusal() {
        Error::MalformedRow {
            plane,
            reason,
            message,
        } => {
            assert_eq!(plane, super::door::SKILL_IMPORT_PLANE, "I2122: the plane");
            assert_eq!(
                reason,
                malformed_row::EDITION2_EARLIER_FORM_OBJECT,
                "I2122: refused by name"
            );
            assert!(
                message.contains("provenance:skill_import:{source}"),
                "I2122: the refusal names the edition-2 row: {message}"
            );
        }
        other => panic!("I2122: the manifest refusal is a MalformedRow, not {other:?}"),
    }
}

/// I2122 on sqlite.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2122_skill_import_is_a_composite_row_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(skill_import(&b)).await;
}

/// I2122 on postgres.
#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2122_skill_import_is_a_composite_row_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(skill_import(&b)).await;
}
