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
//! - **I2115** (v62.0.0, LF-fix2, P5; CC 2.4.1.1 "Never withdrawn";
//!   KR-fix20, the count always wins) — a `withdraws` whose target is held
//!   on a typed plane with no attestation row (an entity revocation) is
//!   REFUSED by name (`withdraws_never_retracts`), read from the target's
//!   statement, and nothing is kept: target first, at the door; composer
//!   first, it waits `link_unheld` and is DROPPED when the revocation lands.
//!   Either way the held set never carries it; the revocation stands.
//!   Unheld, it still waits; a retractable target is withdrawn as before.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;

use super::door_invariants::fixture::*;
use super::names::RowId;

const SCORE_FAM: &str = "coherence_standing:.cohort";
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
    // v62.0.0 (PIN-fix4; CIRISVerify 23.4.1) — a `withdraws` states no
    // dimension under any family; its leaf is its target's.
    let m = vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("refs", map(vec![("target", ref2(&target.0))])),
    ];
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
        // v62.0.0 (PIN-fix4; CIRISVerify 23.4.1) — no dimension: a `withdraws`
        // carries none; its leaf is its target's.
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

/// **I2115** (LF-fix2, P5; KR-fix20) — the three arms of a `withdraws`
/// target, and the held set after the refusal.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) async fn unretractable_body(d: &dyn crate::federation::FederationDirectory) {
    use super::fold::reason::LINK_UNHELD;
    use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
    // KR-fix20 — refused by name: the error's variant and token.
    let refused = |r: Result<StatementOutcome, crate::federation::Error>, what: &str| match r {
        Err(crate::federation::Error::MalformedRow { reason, .. }) => assert_eq!(
            reason,
            crate::federation::malformed_row::WITHDRAWS_NEVER_RETRACTS,
            "{what}"
        ),
        other => panic!("{what}: refused withdraws_never_retracts, got {other:?}"),
    };
    // Nothing of a refused withdrawal is kept: no fold record, no statement.
    let nothing_kept = |w: RowId, what: &'static str| async move {
        assert!(
            d.fold_state(&w).await.unwrap().is_none(),
            "{what}: no fold record"
        );
        assert!(
            d.edition2_voices(&w).await.unwrap().is_empty(),
            "{what}: no statement kept"
        );
        assert!(
            d.get_attestation(&w.hex()).await.unwrap().is_none(),
            "{what}: no row"
        );
    };
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
    // re-folded, REFUSED (KR-fix20) and DROPPED: nothing of it is kept.
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
        None,
        "I2115(2) composer first: the revocation's arrival drops the withdraws"
    );
    nothing_kept(w1, "I2115(2) composer first").await;
    // Target first: the same answer at once, at the door.
    let late = withdraws_revocation(&k, &rev_id, t + 2);
    let w2 = RowId::of_statement(&late).expect("I2115: the withdraws' row id");
    refused(
        put_statement(d, &late, None, INGEST_TIER).await,
        "I2115(2) target first: refused at the door",
    );
    nothing_kept(w2, "I2115(2) target first").await;
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
    // The held set: a re-fold of everything holds neither, and no held row
    // waits on the revocation (`link_unheld`).
    super::fold::refold_all(d)
        .await
        .unwrap_or_else(|e| panic!("I2115: refold_all: {e:?}"));
    let page = super::fold::held_rows(d, None, super::fold::MAX_HELD_PAGE)
        .await
        .unwrap();
    assert!(
        page.iter().all(|h| ![w1, w2].contains(&h.row_id)),
        "I2115 the held set carries neither refused withdraws: {page:?}"
    );
    // A re-offer, of either, is refused again; still nothing kept.
    for (w, st) in [(w1, &early), (w2, &late)] {
        refused(
            put_statement(d, st, None, INGEST_TIER).await,
            "I2115 a re-offer is refused",
        );
        nothing_kept(w, "I2115 after a re-offer").await;
    }

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
