//! **I2914** (v62.0.0, wave P1c; AV-76 at the edition-2 door): the door's
//! pure gates precede its first directory read, on sqlite and postgres.
//!
//! The directory is wrapped in the fault-injecting double with EVERY method
//! it delegates declared erroring, so any directory read answers
//! `federation_backend`:
//!
//! - the instrument can fail: an under-cap statement from a signer with no
//!   held record reaches the key-plane read and draws the injected failure
//!   (the double now delegates the edition-2 store, so the read is seen);
//! - an oversized statement (over `MAX_STATEMENT_BYTES`) is refused
//!   `federation_envelope_too_large` with NO directory read;
//! - an edition-1 row-ref is refused `row_ref_edition_1` with NO directory
//!   read;
//! - a JSON object is refused `earlier_form_object` with NO directory read.
//!
//! **I2916** (wave P1c): a statement under the cap is not refused for its
//! size downstream. The mapped row carries the statement again, as hex,
//! under `ceg_statement`; the envelope size gate bounds that member on its
//! own (at most the statement cap) and does not measure the derived rest
//! against the earlier-form cap. So a 900 KiB statement, its bulk text or a
//! byte string (hex in the projection), passes every size gate and is
//! stored, on sqlite and postgres; an earlier-form envelope with no carried
//! statement is measured exactly as before.
//!
//! **I2917** (wave P1c): a row carrying a statement is exactly its
//! projection, checked FIRST at the attestation door. A small valid
//! statement paired with a large forged envelope (3 MiB of `pad`) is refused
//! `typed_diverges_from_envelope` by `check_carried_projection`, a pure
//! function of the row (it takes no directory, so it reads none, and it
//! never canonicalizes the offered envelope). On sqlite and postgres the
//! same row, also carrying a malformed subject that the door's previous
//! first gate (`validate_subject_key_ids`) refuses with its own error,
//! comes back `typed_diverges_from_envelope`: the projection check runs
//! ahead of every other gate. The honest mapped row passes the pre-check;
//! an earlier-form row (no carried statement) is untouched by it.
//!
//! **I2928** (wave P1e, E3's finding): malformed shapes are REFUSED
//! (`edition2_payload_invalid`), never a panic. At the door, on sqlite and
//! postgres: a scaled member that is not an integer (`score` text, `weight`
//! bytes, `confidence` text), a battery count that is not a uint, a digest
//! that is text or the wrong length (`evidence_refs`, `seat_commitment`), a
//! text `reason`, a non-text `body.note`,
//! a text instant, on a family without a list (a mapped family's own
//! digest of the wrong type is I2919's). The test
//! codec's fallible core refuses a non-number scaled member, a bad instant,
//! a real outside the scaled members and a non-object envelope the same
//! way.
//!
//! Before P1c, `put_statement` read the signer's key plane
//! (`held_keys_for`) first, so the oversized statement drew the read (here
//! `federation_backend`; against a bare backend the retryable
//! `federation_attester_key_unknown`).

use std::sync::Arc;

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;

use super::door::admit_row;
use super::door::{pure_statement_gates, MAX_STATEMENT_BYTES};
use super::door_invariants::fixture::*;
use super::ingest::{
    attestation_of, check_carried_projection, put_statement, StatementOutcome, INGEST_TIER,
    STATEMENT_MEMBER,
};
use super::liveness::HeldKeys;
use crate::federation::directory_double::FaultInjectingDirectory;
use crate::federation::types::{Attestation, SignedAttestation};
use crate::federation::{malformed_row, Error, FederationDirectory};
use ciris_verify_core::edition2::family::SelectContext;

/// The generated double, read for the names of the methods it delegates.
const DOUBLE: &str = include_str!("../directory_double.rs");

/// Every `async fn` the double delegates (each checks its fault table
/// first).
fn every_method() -> Vec<&'static str> {
    DOUBLE
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("async fn "))
        .filter_map(|rest| rest.split('(').next())
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect()
}

/// `inner`, with every delegated method answering an injected backend
/// failure: a door that reads the directory at all draws
/// `federation_backend`.
fn no_reads(inner: Arc<dyn FederationDirectory>) -> FaultInjectingDirectory {
    every_method()
        .into_iter()
        .fold(FaultInjectingDirectory::new(inner), |d, m| d.erroring(m))
}

fn reason(e: &Error) -> String {
    match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    }
}

/// An authored score row (Verify's vector family) by `k`, with `extra`
/// members.
fn statement(
    k: &ciris_crypto::composite::CompositeSigningKey,
    extra: Vec<(&str, Value)>,
) -> Vec<u8> {
    let mut m = vec![
        ("asserted_at", Value::Uint(5_000)),
        ("author", Value::Text(iref(k))),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        ("dimension", Value::Text("coherence_standing:cab:v1".into())),
    ];
    m.extend(extra);
    sign_row_statement(
        k,
        &iref(k),
        &iref(k),
        "scores",
        "coherence_standing:.cohort",
        &map(m),
        vec![],
    )
    .unwrap()
}

fn oversized(k: &ciris_crypto::composite::CompositeSigningKey) -> Vec<u8> {
    let st = statement(
        k,
        vec![("pad", Value::Bytes(vec![0x78; MAX_STATEMENT_BYTES + 1]))],
    );
    assert!(
        st.len() > MAX_STATEMENT_BYTES,
        "I2914 the fixture is oversized"
    );
    st
}

/// I2914: the pure gates alone, no directory.
#[test]
fn i2914_the_pure_gates_need_no_directory() {
    let k = key(150);
    let e = pure_statement_gates(&oversized(&k), &HeldKeys::new()).unwrap_err();
    assert_eq!(e.kind(), "federation_envelope_too_large", "I2914 {e}");
    pure_statement_gates(&statement(&k, vec![]), &HeldKeys::new())
        .expect("I2914 an under-cap statement passes the pure gates, keys or none");
    let old = statement(&k, vec![("refs", map(vec![("target", ref1(&[0x21; 32]))]))]);
    let e = pure_statement_gates(&old, &HeldKeys::new()).unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_ROW_REF_EDITION_1,
        "I2914 {e}"
    );
}

async fn body(inner: Arc<dyn FederationDirectory>) {
    let methods = every_method();
    assert!(
        methods.contains(&"edition2_statements_about"),
        "I2914 the double delegates the key-plane read, or a fault on it is never seen"
    );
    assert!(methods.len() > 100, "I2914 the double's methods were read");
    let dir = no_reads(inner);
    let k = key(151);

    // The instrument can fail: an admissible-size statement is read for.
    let e = put_statement(&dir, &statement(&k, vec![]), None, INGEST_TIER)
        .await
        .unwrap_err();
    assert_eq!(
        e.kind(),
        "federation_backend",
        "I2914 an under-cap statement reaches the directory (the injected failure): {e}"
    );

    // An oversized statement buys no read.
    let e = put_statement(&dir, &oversized(&k), None, INGEST_TIER)
        .await
        .unwrap_err();
    assert_eq!(
        e.kind(),
        "federation_envelope_too_large",
        "I2914 the size gate precedes the signer's key-plane read: {e}"
    );

    // Nor does an edition-1 name, or an earlier-form object.
    let old = statement(&k, vec![("refs", map(vec![("target", ref1(&[0x22; 32]))]))]);
    let e = put_statement(&dir, &old, None, INGEST_TIER)
        .await
        .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_ROW_REF_EDITION_1,
        "I2914 {e}"
    );
    let e = put_statement(&dir, br#"{"attestation_id":"x"}"#, None, INGEST_TIER)
        .await
        .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_EARLIER_FORM_OBJECT,
        "I2914 {e}"
    );
}

/// I2916: the envelope gate, unit.
#[test]
fn i2916_the_envelope_gate_does_not_count_the_carried_statement_twice() {
    use crate::federation::admission::{
        check_envelope_size_admission, MAX_ATTESTATION_ENVELOPE_BYTES,
    };
    let kib900 = 900 * 1024;
    // A mapped row of a 900 KiB statement: the payload's projection plus the
    // statement as hex. Over the cap counted whole; admitted.
    let mapped = serde_json::json!({
        "pad": "x".repeat(kib900),
        STATEMENT_MEMBER: "ab".repeat(kib900),
    });
    check_envelope_size_admission(&mapped)
        .expect("I2916 the carried statement is sized at the door, not again here");
    // The carried member is still bounded: over the statement cap is refused.
    let huge_carried = serde_json::json!({
        STATEMENT_MEMBER: "ab".repeat(MAX_STATEMENT_BYTES + 1),
    });
    let e = check_envelope_size_admission(&huge_carried).unwrap_err();
    assert_eq!(e.kind(), "federation_envelope_too_large", "I2916 {e}");
    // A carrying envelope is sized by its statement alone: its projection is
    // derived from the statement (a byte-string member is hex there), so it
    // may exceed the earlier-form cap and is not measured against it.
    let derived = serde_json::json!({
        "blob": "ab".repeat(kib900),
        STATEMENT_MEMBER: "ab".repeat(kib900),
    });
    check_envelope_size_admission(&derived)
        .expect("I2916 the derived envelope is the statement's size, not its own");
    // An earlier-form envelope (no carried statement): unchanged.
    let earlier = serde_json::json!({ "pad": "x".repeat(MAX_ATTESTATION_ENVELOPE_BYTES + 1) });
    let e = check_envelope_size_admission(&earlier).unwrap_err();
    assert_eq!(e.kind(), "federation_envelope_too_large", "I2916 {e}");
    let earlier_ok = serde_json::json!({ "pad": "x".repeat(kib900) });
    check_envelope_size_admission(&earlier_ok).expect("I2916 earlier form under the cap");
}

/// I2916: a 900 KiB statement from a live key is admitted and stored, its
/// bulk text (`pad`) or a byte string (`blob`, hex in the projection: a
/// ~1.8 MiB derived envelope before the carried copy).
async fn big_body(d: &dyn FederationDirectory) {
    let k = key(152);
    put_statement(d, &key_record(&k, &["user"], 0, None), None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I2916 key record: {e:?}"));
    for (what, bulk) in [
        ("pad", Value::Text("x".repeat(900 * 1024))),
        ("blob", Value::Bytes(vec![0x5c; 900 * 1024])),
    ] {
        big_one(d, &k, what, bulk).await;
    }
}

async fn big_one(
    d: &dyn FederationDirectory,
    k: &ciris_crypto::composite::CompositeSigningKey,
    what: &str,
    bulk: Value,
) {
    let st = statement(k, vec![(what, bulk)]);
    assert!(
        st.len() > 900 * 1024 && st.len() <= MAX_STATEMENT_BYTES,
        "I2916 the {what} fixture is 900 KiB, under the statement cap"
    );
    let out = put_statement(d, &st, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| {
            panic!("I2916 a 900 KiB {what} statement passes the size gates: {e:?}")
        });
    let StatementOutcome::Row { row_id, new: true } = out else {
        panic!("I2916 {what}: {out:?}");
    };
    assert!(
        d.get_attestation(&row_id.hex()).await.unwrap().is_some(),
        "I2916 {what} stored"
    );
}

/// The honest mapped row of `k`'s small statement, and a forgery of it: the
/// same carried statement beside a 3 MiB forged `pad`.
fn honest_and_forged(
    k: &ciris_crypto::composite::CompositeSigningKey,
) -> (Attestation, Attestation) {
    let mut keys = HeldKeys::new();
    keys.insert_record(key_record(k, &["user"], 0, None));
    let st = statement(k, vec![]);
    let admitted = admit_row(&st, &keys, None, SelectContext::default()).unwrap();
    let honest = attestation_of(&admitted, INGEST_TIER).unwrap();
    let mut forged = honest.clone();
    forged.attestation_envelope["pad"] = serde_json::json!("x".repeat(3 * 1024 * 1024));
    (honest, forged)
}

/// I2917: the pre-check, pure.
#[test]
fn i2917_a_forged_envelope_beside_a_valid_statement_is_refused_for_pennies() {
    let k = key(153);
    let (honest, forged) = honest_and_forged(&k);
    check_carried_projection(&honest).expect("I2917 the honest projection passes");
    let e = check_carried_projection(&forged).unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::TYPED_DIVERGES_FROM_ENVELOPE,
        "I2917 {e}"
    );
    // A different row id than the statement's is refused by name.
    let mut renamed = honest.clone();
    renamed.attestation_id = hex::encode([7u8; 32]);
    let e = check_carried_projection(&renamed).unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_ROW_ID_MISMATCH,
        "I2917 {e}"
    );
    // An earlier-form row carries no statement: untouched.
    let mut earlier = honest;
    if let Some(o) = earlier.attestation_envelope.as_object_mut() {
        o.remove(STATEMENT_MEMBER);
    }
    check_carried_projection(&earlier).expect("I2917 no carried statement, no pre-check");
}

/// I2917: wired FIRST at the attestation door.
async fn forged_body(d: &dyn FederationDirectory) {
    let k = key(154);
    let (_, mut forged) = honest_and_forged(&k);
    // The door's previous first gate refuses a malformed subject with its own
    // error; the projection check must answer before it.
    forged.subject_key_ids = vec![String::new()];
    let e = d
        .put_attestation(SignedAttestation {
            attestation: forged.clone(),
        })
        .await
        .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::TYPED_DIVERGES_FROM_ENVELOPE,
        "I2917 the projection check leads the door: {e:?}"
    );
    assert!(
        d.get_attestation(&forged.attestation_id)
            .await
            .unwrap()
            .is_none(),
        "I2917 nothing stored"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2917_a_forged_carrier_is_refused_first_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(forged_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2917_a_forged_carrier_is_refused_first_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(forged_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2916_a_900_kib_statement_is_stored_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(big_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2916_a_900_kib_statement_is_stored_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(big_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2914_pure_gates_precede_the_directory_read_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(Arc::new(b))).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2914_pure_gates_precede_the_directory_read_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(Arc::new(b))).await;
}

// ---- malformed shapes refused, never a panic (I2928) ---------------------

/// The vector-family score row by `k` with `member` set to `value` (the
/// base member of that name replaced, never duplicated).
fn malformed(
    k: &ciris_crypto::composite::CompositeSigningKey,
    family: &str,
    member: &str,
    value: Value,
) -> Vec<u8> {
    let mut m: Vec<(&str, Value)> = vec![
        ("asserted_at", Value::Uint(5_000)),
        ("author", Value::Text(iref(k))),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        ("dimension", Value::Text("coherence_standing:cab:v1".into())),
    ];
    m.retain(|(name, _)| *name != member);
    m.push((member, value));
    sign_row_statement(k, &iref(k), &iref(k), "scores", family, &map(m), vec![]).unwrap()
}

fn digest_of(n: u8, len: usize) -> Value {
    Value::Array(vec![Value::Nint(15), Value::Bytes(vec![n; len])])
}

/// The malformed shapes: `(family, member, value, what)`.
fn malformed_cases() -> Vec<(&'static str, &'static str, Value, &'static str)> {
    let ev = "coherence_standing:.cohort";
    vec![
        (
            ev,
            "score",
            Value::Text("0.75".into()),
            "a scaled member as text",
        ),
        (
            ev,
            "weight",
            Value::Bytes(vec![1, 2]),
            "a scaled member as bytes",
        ),
        (
            ev,
            "confidence",
            Value::Text("x".into()),
            "a scaled member as text",
        ),
        (ev, "passed", Value::Text("3".into()), "a count as text"),
        (
            ev,
            "evidence_refs",
            Value::Array(vec![Value::Text("ab".repeat(32))]),
            "a digest as hex text",
        ),
        (
            ev,
            "evidence_refs",
            Value::Array(vec![digest_of(0x31, 31)]),
            "a digest of 31 bytes",
        ),
        (
            ev,
            "seat_commitment",
            Value::Text("zz".into()),
            "a digest as text",
        ),
        (ev, "reason", Value::Text("spam".into()), "a reason as text"),
        (
            ev,
            "body",
            map(vec![("note", Value::Uint(7))]),
            "a body.note that is not text",
        ),
        (
            ev,
            "valid_until",
            Value::Text("tomorrow".into()),
            "an instant as text",
        ),
    ]
}

// X2 build fix: P1e's codec-level I2928 tested `edition2::codec`, which E0 folded into
// `fixture_switch` (whose codec still panics, E3's finding, E0's to change); the
// door-level I2928 below is kept.

/// I2928: every malformed shape is refused at the door.
async fn malformed_body(d: &dyn FederationDirectory) {
    let k = key(156);
    for (family, member, value, what) in malformed_cases() {
        let st = malformed(&k, family, member, value);
        let e = put_statement(d, &st, None, INGEST_TIER)
            .await
            .expect_err("I2928 a malformed shape is refused");
        assert_eq!(
            reason(&e),
            malformed_row::EDITION2_PAYLOAD_INVALID,
            "I2928 {family}.{member}: {what} is refused, not panicked: {e:?}"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2928_malformed_shapes_are_refused_at_the_door_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(malformed_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2928_malformed_shapes_are_refused_at_the_door_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(malformed_body(&b)).await;
}
