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
//! - **I2115** (v62.0.0, LF-fix2, P5; CC 2.4.1.1 "Never withdrawn") — a
//!   `withdraws` whose target is held on a typed plane with no attestation
//!   row (an entity revocation) SETTLES: HELD `withdraws_not_admitted`, read
//!   from the target's statement, whichever arrived first, and never again
//!   `link_unheld`; the revocation stands. Unheld, it still waits; a
//!   retractable target is withdrawn as before.

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

/// A self-revocation of `k` (`revocation:agent:compromise:v1`), the typed
/// revocation plane's row (I3153's shape): it lands in
/// `federation_revocations` and its statement, and no attestation row
/// carries its id.
fn self_revocation(k: &CompositeSigningKey, at_ms: u64) -> Vec<u8> {
    use super::typed::{revocation_payload, REVOCATION_PREFIX};
    let instant =
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(i64::try_from(at_ms).unwrap())
            .unwrap();
    let p = revocation_payload(
        &iref(k),
        "agent",
        "compromise",
        instant,
        instant,
        None,
        None,
        None,
        at_ms,
    )
    .unwrap();
    sign_row_statement(
        k,
        &iref(k),
        &iref(k),
        "scores",
        &ciris_verify_core::namespace_match::family_id(REVOCATION_PREFIX),
        &p,
        vec![],
    )
    .unwrap()
}

/// A `withdraws` of the revocation family naming `target`, by `k` (the
/// revocation's own signer: rule 1 would admit it on a retractable plane).
fn withdraws_revocation(k: &CompositeSigningKey, target: &RowId, at_ms: u64) -> Vec<u8> {
    use super::typed::REVOCATION_PREFIX;
    let m = map(vec![
        ("asserted_at", Value::Uint(at_ms)),
        ("author", Value::Text(iref(k))),
        (
            "dimension",
            Value::Text("revocation:agent:compromise:v1".into()),
        ),
        ("refs", map(vec![("target", ref2(&target.0))])),
    ]);
    sign_row_statement(
        k,
        &iref(k),
        &iref(k),
        "withdraws",
        &ciris_verify_core::namespace_match::family_id(REVOCATION_PREFIX),
        &m,
        vec![],
    )
    .unwrap()
}

/// **I2115** (LF-fix2, P5) — the three arms of a `withdraws` target, and the
/// held set after the settle.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) async fn unretractable_body(d: &dyn crate::federation::FederationDirectory) {
    use super::fold::reason::{LINK_UNHELD, WITHDRAWS_NOT_ADMITTED};
    use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
    let why = |row: RowId| async move {
        super::fold::why_held(d, &row)
            .await
            .unwrap()
            .map(|h| h.reason)
    };
    let k = key(140);
    put_statement(d, &key_record(&k, &["user"], 0, None), None, INGEST_TIER)
        .await
        .unwrap();
    let t = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();
    let rev = self_revocation(&k, t);
    let rev_id = RowId::of_statement(&rev).expect("I2115: the revocation's row id");

    // (1) Not held: the withdraws WAITS (`link_unheld`), as before.
    let early = withdraws_revocation(&k, &rev_id, t + 1);
    let StatementOutcome::Pending { row_id: w1, .. } = put_statement(d, &early, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I2115(1): held, never refused: {e:?}"))
    else {
        panic!("I2115(1): an unheld target holds the withdraws");
    };
    assert_eq!(
        why(w1).await,
        Some(LINK_UNHELD.to_owned()),
        "I2115(1) an unheld target: the withdraws waits"
    );

    // (2) The revocation lands on its typed plane; the waiting withdraws is
    // re-folded and SETTLES: not admitted, never `link_unheld` again.
    let landed = put_statement(d, &rev, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I2115(2): the self-revocation lands: {e:?}"));
    assert!(
        matches!(landed, StatementOutcome::Row { .. }),
        "I2115(2) the revocation concludes on its plane: {landed:?}"
    );
    assert!(
        d.get_attestation(&rev_id.hex()).await.unwrap().is_none(),
        "I2115(2) precondition: no attestation row carries the revocation's id \
         (else the withdraws resolves as before and this witnesses nothing)"
    );
    assert_eq!(
        why(w1).await,
        Some(WITHDRAWS_NOT_ADMITTED.to_owned()),
        "I2115(2) composer first: the revocation's arrival settles the withdraws"
    );
    // Target first: the same verdict at once.
    let late = withdraws_revocation(&k, &rev_id, t + 2);
    let StatementOutcome::Pending { row_id: w2, .. } = put_statement(d, &late, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I2115(2): held, never refused: {e:?}"))
    else {
        panic!("I2115(2): a never-withdrawn target concludes no withdraws");
    };
    assert_eq!(
        why(w2).await,
        Some(WITHDRAWS_NOT_ADMITTED.to_owned()),
        "I2115(2) target first: settled not admitted"
    );
    for w in [w1, w2] {
        assert!(
            d.get_attestation(&w.hex()).await.unwrap().is_none(),
            "I2115(2) the withdraws concludes nothing"
        );
    }
    // The revocation stands (CC 2.4.1.1: withdrawn by nobody, its own
    // signer included).
    assert!(
        !d.edition2_voices(&rev_id).await.unwrap().is_empty(),
        "I2115(2) the revocation's statement stands"
    );
    let key_row = d.lookup_public_key(&iref(&k)).await.unwrap().unwrap();
    let digest = crate::federation::key_digest::Sha256Ed25519Raw::from_pubkey_base64(
        &key_row.pubkey_ed25519_base64,
    )
    .unwrap()
    .to_hex();
    assert!(
        d.revocations_for_subject(&digest)
            .await
            .unwrap()
            .iter()
            .any(|r| r.revocation_id == rev_id.hex()),
        "I2115(2) the revocation stands on its plane"
    );
    // The held set: a re-fold of everything keeps both settled, and no held
    // row waits on the revocation (`link_unheld`) any more.
    super::fold::refold_all(d)
        .await
        .unwrap_or_else(|e| panic!("I2115: refold_all: {e:?}"));
    let page = super::fold::held_rows(d, None, super::fold::MAX_HELD_PAGE)
        .await
        .unwrap();
    for w in [w1, w2] {
        let entry = page
            .iter()
            .find(|h| h.row_id == w)
            .unwrap_or_else(|| panic!("I2115: the settled withdraws is held: {page:?}"));
        assert_eq!(
            entry.reason, WITHDRAWS_NOT_ADMITTED,
            "I2115 the held set carries the settle, never the wait"
        );
    }
    assert!(
        page.iter()
            .filter(|h| [w1, w2].contains(&h.row_id))
            .all(|h| h.reason != LINK_UNHELD),
        "I2115 no settled withdraws is carried as waiting"
    );
    // A re-offer holds it again, unchanged.
    let again = put_statement(d, &late, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I2115: re-offer: {e:?}"));
    assert!(
        matches!(again, StatementOutcome::Pending { new: false, .. }),
        "I2115 still held: {again:?}"
    );
    assert_eq!(why(w2).await, Some(WITHDRAWS_NOT_ADMITTED.to_owned()));

    // (3) A retractable target (a scores row) is withdrawn by its producer
    // as before: admitted, a typed row.
    let target = score(&k, 5_000);
    let StatementOutcome::Row { row_id: st, .. } =
        put_statement(d, &target, None, INGEST_TIER).await.unwrap()
    else {
        panic!("I2115(3) the score row");
    };
    let out = put_statement(d, &withdraws(&k, SCORE_FAM, &st, 6_000), None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I2115(3) admitted: {e:?}"));
    let StatementOutcome::Row { row_id: w3, .. } = out else {
        panic!("I2115(3) a retractable target's withdraws concludes: {out:?}");
    };
    assert!(
        d.get_attestation(&w3.hex()).await.unwrap().is_some(),
        "I2115(3) the withdraws is a typed row"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2115_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(unretractable_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2115_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(unretractable_body(&b)).await;
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
