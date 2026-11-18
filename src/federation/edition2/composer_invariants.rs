//! **I2105** (v62.0.0, JSON-cut slice A): a composer's target, on sqlite and
//! postgres.
//!
//! - A `withdraws` naming a held row of its own family is admitted, and the
//!   mapped row's `references_attestation_id` is the target's node-computed
//!   row id (from `refs.target`, never a peer string).
//! - A composer whose family is not its target's is
//!   `composer_family_mismatch`: (v62.0.0, wave GC6, **I3870**) HELD,
//!   concluding nothing, with that reason (a key-plane family too: G0 v4
//!   holds it back from the key plane), and held again whichever of
//!   composer and target arrived first.
//! - A composer naming a row this node does not hold waits: HELD,
//!   `link_unheld` (G0 v5.1), re-folded when the target lands.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;

use super::door_invariants::fixture::*;
use super::names::RowId;

const SCORE_FAM: &str = "evidence:.suite:.kind:.cell:.prefix";
/// Built so no literal reads as a family prefix to the family-rules
/// discovery scan.
const SCORE_DIM: &str = concat!("evidence", ":safety_battery:capture:a:b:v1");

fn score(k: &CompositeSigningKey, at: u64) -> Vec<u8> {
    let m = map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        ("dimension", Value::Text(SCORE_DIM.into())),
    ]);
    sign_row_statement(k, &iref(k), &iref(k), "scores", SCORE_FAM, &m, vec![]).unwrap()
}

fn withdraws(k: &CompositeSigningKey, family: &str, target: &RowId, at: u64) -> Vec<u8> {
    let mut m = vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("refs", map(vec![("target", ref2(&target.0))])),
    ];
    // A dimension is carried only under the family that binds it.
    if family == SCORE_FAM {
        m.push(("dimension", Value::Text(SCORE_DIM.into())));
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
    let record = key_record(&k, &["user"], 0, None);
    put_statement(d, &record, None, INGEST_TIER).await.unwrap();
    let target = score(&k, 5_000);
    let StatementOutcome::Row { row_id: t, .. } =
        put_statement(d, &target, None, INGEST_TIER).await.unwrap()
    else {
        panic!("I2105 target");
    };
    // Unheld target: waits (G0 v5.1: HELD, reason `link_unheld`, re-folded
    // when the target lands).
    let out = put_statement(
        d,
        &withdraws(&k, SCORE_FAM, &RowId([0x77; 32]), 6_000),
        None,
        INGEST_TIER,
    )
    .await
    .unwrap_or_else(|e| panic!("I2105 unheld is held: {}", reason(&e)));
    let StatementOutcome::Pending { row_id: u, .. } = out else {
        panic!("I2105 unheld: {out:?}");
    };
    assert_eq!(
        super::fold::why_held(d, &u)
            .await
            .unwrap()
            .map(|h| h.reason),
        Some(super::fold::reason::LINK_UNHELD.to_owned()),
        "I2105 unheld"
    );
    // Another family than the target's (a key-plane family, `key:revocation`):
    // v62.0.0 (wave GC6, G0 v4) — HELD with reason `composer_family_mismatch`,
    // never refused, and (held back) never read as key plane.
    let out = put_statement(
        d,
        &withdraws(&k, "key:revocation", &t, 6_000),
        None,
        INGEST_TIER,
    )
    .await
    .unwrap_or_else(|e| panic!("I2105/I3870 mismatch is held: {}", reason(&e)));
    let StatementOutcome::Pending { row_id: km, .. } = out else {
        panic!("I2105/I3870 mismatch held: {out:?}");
    };
    assert_eq!(
        super::fold::why_held(d, &km)
            .await
            .unwrap()
            .map(|h| h.reason),
        Some(malformed_row::COMPOSER_FAMILY_MISMATCH.to_owned()),
        "I2105 mismatch"
    );
    // I3870 (wave GC6; CC 2.7.3) — a composer of a non-key family whose
    // target (here the signer's own key record) is of another family is
    // HELD, concluding nothing, with reason `composer_family_mismatch`.
    let record_id = RowId::of_statement(&record).expect("I3870: the record's row id");
    let mismatched = withdraws(&k, SCORE_FAM, &record_id, 6_500);
    let out = put_statement(d, &mismatched, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I3870: held, never refused: {e:?}"));
    let StatementOutcome::Pending { row_id: m, new } = out else {
        panic!("I3870: held: {out:?}");
    };
    assert!(new, "I3870: the statement is kept");
    assert!(
        d.get_attestation(&m.hex()).await.unwrap().is_none(),
        "I3870: no typed row: it concludes nothing"
    );
    let why = super::fold::why_held(d, &m)
        .await
        .unwrap()
        .expect("I3870: a held reason");
    assert_eq!(
        why.reason,
        super::fold::reason::COMPOSER_FAMILY_MISMATCH,
        "I3870: the reason is the refusal token it replaces"
    );
    // A re-offer (a re-fold) holds it again, unchanged.
    let again = put_statement(d, &mismatched, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I3870: re-offer: {e:?}"));
    assert!(
        matches!(again, StatementOutcome::Pending { new: false, .. }),
        "I3870: still held: {again:?}"
    );
    // Composer FIRST (another key's record as the target): held while its
    // target is unheld (`link_unheld`), and RE-FOLDED when the target lands,
    // to the same held answer as target first (`composer_family_mismatch`).
    let k3 = key(132);
    let record3 = key_record(&k3, &["user"], 0, None);
    let record3_id = RowId::of_statement(&record3).expect("I3870: row id");
    let early = withdraws(&k, SCORE_FAM, &record3_id, 6_600);
    let out = put_statement(d, &early, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I3870: held while its target is unheld: {e:?}"));
    let StatementOutcome::Pending { row_id: m3, .. } = out else {
        panic!("I3870: held: {out:?}");
    };
    assert_eq!(
        super::fold::why_held(d, &m3)
            .await
            .unwrap()
            .map(|h| h.reason),
        Some(super::fold::reason::LINK_UNHELD.to_owned()),
        "I3870: the composer waits for its target"
    );
    put_statement(d, &record3, None, INGEST_TIER).await.unwrap();
    assert_eq!(
        super::fold::why_held(d, &m3)
            .await
            .unwrap()
            .map(|h| h.reason),
        Some(super::fold::reason::COMPOSER_FAMILY_MISMATCH.to_owned()),
        "I3870: re-folded on the target's arrival: either arrival order ends held, \
         with the same reason"
    );
    assert!(
        d.get_attestation(&m3.hex()).await.unwrap().is_none(),
        "I3870: it concludes nothing"
    );
    // The target's family: admitted, naming the target by its row id.
    let StatementOutcome::Row { row_id: w, .. } =
        put_statement(d, &withdraws(&k, SCORE_FAM, &t, 6_000), None, INGEST_TIER)
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
