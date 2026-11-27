//! **I2870–I2873** (v62.0.0, JSON-cut slice F; CC 2.6.1.12): the
//! earlier-form doors are shut, on sqlite and postgres.
//!
//! - I2870: [`EARLIER_FORM_DOORS_SHUT`] is `true`, with no test scope forcing
//!   it, and the one shared refusal refuses every plane by name
//!   (`earlier_form_object`), naming the plane.
//! - I2871: every attestation-plane trait door refuses a JSON row by name:
//!   `put_attestation`, `put_attestation_authored`,
//!   `put_attestation_with_origin` (each origin), `put_attestation_synced`
//!   and `apply_replicated_attestation`.
//! - I2872: every key-record trait door refuses a key record offered as an
//!   earlier-form object by name: `put_public_key`,
//!   `apply_replicated_key_record`, `store_rebound_key_record` and
//!   `store_invalid_replaced_key_record` (C5 deleted `adopt_scrub_upgrade`). The
//!   record offered is this node's own projection of an admitted edition-2
//!   `key:record`, so the refusal is the form's, not the record's.
//! - I2873: after every refusal, the edition-2 statement still lands through
//!   the edition-2 entry: shutting the earlier form shuts nothing else.
//!
//! The other doors (families, communities, their membership stages,
//! occurrences, revocations, location proofs, touch claims, trust grants,
//! accord payloads and evidence, lineage cosigns, transport destinations,
//! key grants, purges, roster changes) reach the same refusal unconditionally
//! before any parse; `scripts/earlier_form_doors.py` holds that from disk,
//! door by door, for the trait, PyO3, capsule and HTTP surfaces.

use super::door::{earlier_form_doors_shut, refuse_earlier_form, EARLIER_FORM_DOORS_SHUT};
use crate::federation::{malformed_row, Error};
#[cfg(any(feature = "sqlite", feature = "postgres"))]
use {
    super::door::admit_row,
    super::door_invariants::fixture::*,
    super::ingest::{attestation_of, put_statement, INGEST_TIER, STATEMENT_MEMBER},
    super::liveness::HeldKeys,
    crate::federation::replication::admission::WriteOrigin,
    crate::federation::types::{Attestation, SignedAttestation, SignedKeyRecord},
    crate::federation::FederationDirectory,
    ciris_verify_core::cde::Value,
    ciris_verify_core::edition2::family::SelectContext,
    ciris_verify_core::edition2::sign_row_statement,
};

/// Every plane name a door passes to [`refuse_earlier_form`]: the Rust doors,
/// the PyO3 doors (D1) and the capsule's classifier (D2), read from their
/// call sites. `scripts/earlier_form_doors.py` holds that each door calls it.
const PLANES: &[&str] = &[
    "accord_evidence",
    "attestation",
    "community",
    "delivery_ack",
    "family",
    "genesis_bundle",
    "group_roster",
    "identity_occurrence",
    "identity_occurrence_revocation",
    "key_grant",
    "key_record",
    "lineage_head_cosign",
    "location_proof",
    "purge",
    "revocation",
    "touch_claim",
    "transport_destination",
    "trust_grant",
];

fn reason(e: &Error) -> &'static str {
    match e {
        Error::MalformedRow { reason, .. } => reason,
        other => other.kind(),
    }
}

/// The refusal, by name, or a panic naming the door that admitted.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn refused<T>(door: &str, r: Result<T, Error>) -> Error {
    match r {
        Err(e) => e,
        Ok(_) => panic!("I2871/I2872: `{door}` admitted an object of the earlier form"),
    }
}

#[test]
fn i2870_the_doors_are_shut() {
    const { assert!(EARLIER_FORM_DOORS_SHUT, "I2870: slice F shut the doors") };
    // No test scope forces it: the node's own switch is on.
    assert!(earlier_form_doors_shut(), "I2870");
    for &plane in PLANES {
        let e = refuse_earlier_form(plane).unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::EDITION2_EARLIER_FORM_OBJECT,
            "I2870: `{plane}` refuses by name"
        );
        assert!(
            e.to_string().contains(plane),
            "I2870: the refusal names its door `{plane}`: {e}"
        );
    }
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn score_row(k: &ciris_crypto::composite::CompositeSigningKey, at: u64) -> Vec<u8> {
    let payload = map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        ("dimension", Value::Text("coherence_standing:cab:v1".into())),
    ]);
    sign_row_statement(
        k,
        &iref(k),
        &iref(k),
        "scores",
        "coherence_standing:.cohort",
        &payload,
        vec![],
    )
    .unwrap()
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) async fn body(d: &dyn FederationDirectory) {
    let k = key(71);
    let record = key_record(&k, &["user"], 0, None);
    put_statement(d, &record, None, INGEST_TIER)
        .await
        .expect("I2873: the edition-2 key:record lands");
    let mut keys = HeldKeys::new();
    keys.insert_record(record);

    // I2871 — a JSON row: the edition-2 mapping with its statement stripped.
    let st = score_row(&k, 6_000);
    let mapped = attestation_of(
        &admit_row(&st, &keys, None, SelectContext::default()).unwrap(),
        INGEST_TIER,
    )
    .unwrap();
    let mut json_row: Attestation = mapped.clone();
    json_row
        .attestation_envelope
        .as_object_mut()
        .unwrap()
        .remove(STATEMENT_MEMBER);
    let signed = || SignedAttestation {
        attestation: json_row.clone(),
    };
    let attestation_doors: Vec<(&str, Error)> = vec![
        (
            "put_attestation",
            refused("put_attestation", d.put_attestation(signed()).await),
        ),
        (
            "put_attestation_authored",
            refused(
                "put_attestation_authored",
                d.put_attestation_authored(signed()).await,
            ),
        ),
        (
            "put_attestation_with_origin(Wire)",
            refused(
                "put_attestation_with_origin(Wire)",
                d.put_attestation_with_origin(signed(), WriteOrigin::Wire)
                    .await,
            ),
        ),
        (
            "put_attestation_with_origin(Authored)",
            refused(
                "put_attestation_with_origin(Authored)",
                d.put_attestation_with_origin(signed(), WriteOrigin::Authored)
                    .await,
            ),
        ),
        (
            "put_attestation_with_origin(Sync)",
            refused(
                "put_attestation_with_origin(Sync)",
                d.put_attestation_with_origin(
                    signed(),
                    WriteOrigin::Sync {
                        peer_key_id: iref(&k),
                    },
                )
                .await,
            ),
        ),
        (
            "put_attestation_synced",
            refused(
                "put_attestation_synced",
                d.put_attestation_synced(signed(), &iref(&k)).await,
            ),
        ),
        (
            "apply_replicated_attestation",
            refused(
                "apply_replicated_attestation",
                d.apply_replicated_attestation(signed()).await,
            ),
        ),
    ];
    for (door, e) in &attestation_doors {
        assert_eq!(
            reason(e),
            malformed_row::EDITION2_EARLIER_FORM_OBJECT,
            "I2871: `{door}` refuses the JSON row by name: {e}"
        );
    }

    // I2872 — this node's own projection of the admitted key:record, offered
    // back as an earlier-form object.
    let projected = d
        .lookup_public_key(&iref(&k))
        .await
        .unwrap()
        .expect("I2872: the key:record is projected into the key store");
    let offer = || SignedKeyRecord {
        record: projected.clone(),
    };
    let key_doors: Vec<(&str, Error)> = vec![
        (
            "put_public_key",
            refused("put_public_key", d.put_public_key(offer()).await),
        ),
        (
            "apply_replicated_key_record",
            refused(
                "apply_replicated_key_record",
                d.apply_replicated_key_record(offer()).await,
            ),
        ),
        (
            "store_rebound_key_record",
            refused(
                "store_rebound_key_record",
                d.store_rebound_key_record(offer()).await,
            ),
        ),
        (
            "store_invalid_replaced_key_record",
            refused(
                "store_invalid_replaced_key_record",
                d.store_invalid_replaced_key_record(offer()).await,
            ),
        ),
    ];
    for (door, e) in &key_doors {
        assert_eq!(
            reason(e),
            malformed_row::EDITION2_EARLIER_FORM_OBJECT,
            "I2872: `{door}` refuses the key record by name: {e}"
        );
    }
    // Refused, so unchanged: the held record is still the projection.
    assert_eq!(
        d.lookup_public_key(&iref(&k)).await.unwrap().as_ref(),
        Some(&projected),
        "I2872: a refused door wrote nothing"
    );

    // I2873 — the edition-2 door stays open.
    put_statement(d, &st, None, INGEST_TIER)
        .await
        .expect("I2873: the edition-2 statement lands after every refusal");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2871_i2872_i2873_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2871_i2872_i2873_postgres() {
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
