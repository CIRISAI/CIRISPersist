//! **I3027–I3029, I3031** (wave O1; CC 4.2.6): a recovery key is refused as a
//! signing key by its public key material, at the row door, on sqlite and
//! postgres. The genesis lineage is C2's test ceremony (`fixture_genesis`)
//! through C1's import door.
//!
//! - I3027: after a recovery spends holder 1's recovery key, a row signed by
//!   that key's material as the holder is refused
//!   `recovery_key_is_not_a_signer`, finally (not a wait), and no voice or
//!   row of it is held.
//! - I3028: the recovery commits a next recovery key whose record no bundle
//!   names; its own self-signed `key:record` is refused by the same token
//!   (the statement carries the key material), and nothing is held.
//! - I3031 (pure): a commitment is opened as the reader opens it, over the
//!   one recovery key (CC 4.2.6): a key whose single-key commitment is held
//!   is a recovery key, and a key inside a several-key commitment matches
//!   nothing (no such commitment counts a recovery either).
//! - I3029: controls. An ordinary key's record is admitted with the lineage
//!   held, and before any genesis is held the recovery key's own record is
//!   not refused by this rule (nothing commits to it yet).

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;

use super::door_invariants::fixture::{key_record, map};
use super::fixture_genesis::{
    bundle_v2, install_ceremony_v2, install_v2, recover_v2, test_key, HOLDER_SEEDS,
    NEXT_RECOVERY_SEED_OFFSET, RECOVERY_SEED_OFFSET,
};
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::names::RowId;
use crate::federation::{malformed_row, Error, FederationDirectory};

fn reason(e: &Error) -> String {
    match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    }
}

async fn nothing_held(d: &dyn FederationDirectory, st: &[u8], what: &str) {
    let id = RowId::of_statement(st).expect("a row id");
    assert!(
        d.edition2_voices(&id).await.unwrap().is_empty(),
        "{what}: no voice held"
    );
    assert!(
        d.get_attestation(&id.hex()).await.unwrap().is_none(),
        "{what}: no row held"
    );
}

pub(crate) async fn body(d: &dyn FederationDirectory) {
    let n = HOLDER_SEEDS[0];
    let spent = test_key(n + RECOVERY_SEED_OFFSET);
    let next = test_key(n + NEXT_RECOVERY_SEED_OFFSET);

    // I3029 (control, pre-genesis): nothing commits to the key yet.
    let pre = key_record(&next, &["user"], 0, None);
    let out = Box::pin(put_statement(d, &pre, None, INGEST_TIER)).await;
    assert!(
        !matches!(&out, Err(e) if reason(e) == malformed_row::RECOVERY_KEY_IS_NOT_A_SIGNER),
        "I3029: no bundle held, no recovery key: {out:?}"
    );

    install_v2(d).await.unwrap();
    let r = recover_v2(bundle_v2(), n);
    install_ceremony_v2(d, &r).await.unwrap();
    let holder = bundle_v2().holder_identity_ref(0).to_owned();

    // I3027: the spent recovery key signs as the holder.
    let payload = map(vec![
        ("author", Value::Text(holder.clone())),
        ("asserted_at", Value::Uint(r.asserted_at_ms + 1000)),
    ]);
    let row = sign_row_statement(
        &spent,
        &holder,
        &holder,
        "scores",
        "key:revocation",
        &payload,
        vec![],
    )
    .unwrap();
    let e = Box::pin(put_statement(d, &row, None, INGEST_TIER))
        .await
        .expect_err("I3027: admitted");
    assert_eq!(
        reason(&e),
        malformed_row::RECOVERY_KEY_IS_NOT_A_SIGNER,
        "I3027: {e:?}"
    );
    assert!(
        !matches!(e, Error::AttesterKeyUnknown { .. } | Error::Backend(_)),
        "I3027: final"
    );
    nothing_held(d, &row, "I3027").await;

    // I3028: the committed (unspent) next recovery key's own record.
    let rec = key_record(&next, &["user"], r.asserted_at_ms, None);
    let e = Box::pin(put_statement(d, &rec, None, INGEST_TIER))
        .await
        .expect_err("I3028: admitted");
    assert_eq!(
        reason(&e),
        malformed_row::RECOVERY_KEY_IS_NOT_A_SIGNER,
        "I3028: {e:?}"
    );
    nothing_held(d, &rec, "I3028").await;

    // I3029 (control): an ordinary key with the lineage held.
    let plain = key_record(&test_key(200), &["user"], 0, None);
    assert!(
        matches!(
            Box::pin(put_statement(d, &plain, None, INGEST_TIER)).await,
            Ok(StatementOutcome::KeyPlane { .. })
        ),
        "I3029: an ordinary key is admitted"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3027_to_i3029_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3027_to_i3029_postgres() {
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

#[test]
fn i3031_a_commitment_is_opened_over_one_key() {
    use super::door_invariants::fixture::{key, kid};
    use super::recovery_signer::is_recovery_key;
    use ciris_verify_core::edition2::recovery::recovery_commitment;
    use std::collections::BTreeSet;
    let rk = key(90);
    let other = key(91);
    let rec = key_record(&rk, &["user"], 0, None);
    let one: BTreeSet<_> = [recovery_commitment(std::slice::from_ref(rk.public_key()))].into();
    assert!(
        is_recovery_key(&kid(&rk), [rec.as_slice()], &one),
        "I3031: the one-key commitment"
    );
    let set: BTreeSet<_> = [recovery_commitment(&[
        rk.public_key().clone(),
        other.public_key().clone(),
    ])]
    .into();
    assert!(
        !is_recovery_key(&kid(&rk), [rec.as_slice()], &set),
        "I3031: a several-key digest is not the reader's commitment"
    );
}
