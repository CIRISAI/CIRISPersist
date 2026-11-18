//! **I2915** (v62.0.0, wave P1c; E1's finding): the edition-2 mapping fills
//! the typed `weight` column from the payload's fixed6 `weight`.
//!
//! - pure ([`attestation_of`] over an admitted `self:delegates_to` row, as
//!   the door hands it on): payload `weight` 2_500_000 is the column
//!   `Some(2.5)` and the mirror's `weight` 2.5; a negative fixed6 is its
//!   negative real; no `weight` is `None` and the mirror names none;
//! - store-backed, sqlite and postgres: a weighted row offered through
//!   `put_statement` is stored with `weight` 2.5, and the weighted fold that
//!   reads the column (`build_trust_topology`, `weight.unwrap_or(1.0)`)
//!   reads 2.5, not the 1.0 a NULL column gave;
//! - a mapped row whose `weight` column was altered after mapping, put
//!   through the JSON door, is refused `typed_diverges_from_envelope` (the
//!   row-mirror gate or `verify_carried`) and nothing is stored.
//!
//! **I2924** (wave P1e, E10's finding): the mapping renders every hash
//! digest as the 64-lowercase-hex text the earlier-form readers read:
//! `evidence_refs` (a sequence) as an array of hex, a family's own digest
//! member (`takedown_notice`'s `content_sha256`) as hex. On sqlite and
//! postgres, an edition-2 score whose `evidence_refs` cites a blob is found
//! by the purge derivation (`steward_purge::human_subject_records` over the
//! blob record): its subject, a person, is named, not "no row binds this
//! blob".
//!
//! **I2927** (wave P1e, E3's finding): the peer de-admission dimension is
//! the registered `revocation:{entity_type}:{reason}` shape
//! (`revocation:peer_admission:deadmitted:v1`): Verify's matcher resolves it
//! to the family, the revocation list leaves the `peer_admission` leaf to
//! its own (scores) shape, and on sqlite and postgres an edition-2
//! de-admission row is admitted and stored, and the de-admission gate then
//! refuses the peer's writes. The readers match the stem, so the earlier
//! spelling still reads as a de-admission.
//!
//! No kernel module reads `Attestation.weight` (read-checked: `kernel::trust`
//! / `kernel::owner` build `KRow`s from ids, names and signers; the kernel's
//! `weights` are a `weighted:` rubric's, from the group record). The column's
//! readers are `topology` and `replication::trust_scoring`.

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::sign_row_statement;

use super::door::{admit_row, AdmittedRow};
use super::door_invariants::fixture::*;
use super::ingest::{attestation_of, put_statement, StatementOutcome, INGEST_TIER};
use super::liveness::HeldKeys;
use super::names::RowId;
use crate::federation::types::SignedAttestation;
use crate::federation::{malformed_row, Error, FederationDirectory};

fn reason(e: &Error) -> String {
    match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    }
}

/// An admitted `self:delegates_to` row as the door hands it to the mapping,
/// carrying `weight` (fixed6) when given.
fn delegation(weight: Option<Value>) -> AdmittedRow {
    let (a, b) = (key(160), key(161));
    let mut m = vec![
        ("asserted_at", Value::Uint(5_000)),
        ("author", Value::Text(iref(&a))),
    ];
    if let Some(w) = weight {
        m.push(("weight", w));
    }
    let payload = map(m);
    let bytes = sign_row_statement(
        &a,
        &iref(&a),
        &iref(&b),
        "delegates_to",
        "self:delegates_to",
        &payload,
        vec![],
    )
    .unwrap();
    AdmittedRow {
        row_id: RowId([0x5a; 32]),
        statement_id: [0x5b; 32],
        kid: kid(&a),
        iss: iref(&a),
        sub: iref(&b),
        row_type: "delegates_to".into(),
        family: "self:delegates_to".into(),
        author: Some(iref(&a)),
        asserted_at_ms: 5_000,
        payload,
        names: Vec::new(),
        role: None,
        bytes,
    }
}

/// I2915: the mapping fills the column, and the mirror binds it.
#[test]
fn i2915_the_mapping_fills_the_weight_column() {
    let a = attestation_of(&delegation(Some(Value::Uint(2_500_000))), INGEST_TIER).unwrap();
    assert_eq!(a.weight, Some(2.5), "I2915 fixed6 2_500_000 is 2.5");
    assert_eq!(
        a.attestation_envelope["row"]["weight"].as_f64(),
        Some(2.5),
        "I2915 the mirror binds the weight"
    );
    assert_eq!(
        a.attestation_envelope["weight"].as_f64(),
        Some(2.5),
        "I2915 the envelope's real agrees"
    );
    // -1 - 499_999 = -500_000: a negative fixed6.
    let n = attestation_of(&delegation(Some(Value::Nint(499_999))), INGEST_TIER).unwrap();
    assert_eq!(n.weight, Some(-0.5), "I2915 a negative weight");
    let none = attestation_of(&delegation(None), INGEST_TIER).unwrap();
    assert_eq!(none.weight, None, "I2915 no weight is None, not 1.0");
    assert!(
        none.attestation_envelope["row"].get("weight").is_none(),
        "I2915 the mirror names no weight when the payload carries none"
    );
}

/// An authored, weighted score row (Verify's vector family) by `k`, about
/// `on`.
fn weighted_score(k: &ciris_crypto::composite::CompositeSigningKey, on: &str) -> Vec<u8> {
    weighted(k, on, 5_000)
}

/// The same row by `k` about itself, at `at`.
fn weighted_score_at(k: &ciris_crypto::composite::CompositeSigningKey, at: u64) -> Vec<u8> {
    weighted(k, &iref(k), at)
}

fn weighted(k: &ciris_crypto::composite::CompositeSigningKey, on: &str, at: u64) -> Vec<u8> {
    let payload = map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        ("weight", Value::Uint(2_500_000)),
        (
            "dimension",
            Value::Text("evidence:safety_battery:capture:a:b:v1".into()),
        ),
    ]);
    sign_row_statement(
        k,
        &iref(k),
        on,
        "scores",
        "evidence:.suite:.kind:.cell:.prefix",
        &payload,
        vec![],
    )
    .unwrap()
}

async fn body(d: &dyn FederationDirectory) {
    let k = key(162);
    put_statement(d, &key_record(&k, &["user"], 0, None), None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I2915 key record: {e:?}"));
    let st = weighted_score(&k, &iref(&k));
    let out = put_statement(d, &st, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I2915 a weighted row admits: {e:?}"));
    let StatementOutcome::Row { row_id, .. } = out else {
        panic!("I2915: {out:?}");
    };
    let stored = d
        .get_attestation(&row_id.hex())
        .await
        .unwrap()
        .expect("I2915 stored under its row id");
    assert_eq!(stored.weight, Some(2.5), "I2915 the stored weight column");

    let topo = crate::federation::build_trust_topology(
        d,
        &crate::federation::FederationDirectoryFilter {
            granter_key: Some(iref(&k)),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(topo.edges.len(), 1, "I2915 one edge");
    assert!(
        (topo.edges[0].weight - 2.5).abs() < 1e-9,
        "I2915 the weighted fold reads 2.5, got {}",
        topo.edges[0].weight
    );

    // The column is the statement's: a fresh mapped row (not held) whose
    // weight column was altered after mapping is refused at the JSON door,
    // by the mirror gate or by `verify_carried` (both
    // `typed_diverges_from_envelope`), and nothing is stored.
    let mut keys = HeldKeys::new();
    keys.insert_record(key_record(&k, &["user"], 0, None));
    let st2 = weighted_score_at(&k, 6_000);
    let admitted = admit_row(&st2, &keys, None, SelectContext::default()).unwrap();
    let mut forged = attestation_of(&admitted, INGEST_TIER).unwrap();
    assert_eq!(forged.weight, Some(2.5), "I2915 the mapping");
    forged.weight = Some(9.0);
    let e = d
        .put_attestation(SignedAttestation {
            attestation: forged,
        })
        .await
        .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::TYPED_DIVERGES_FROM_ENVELOPE,
        "I2915 a weight column that is not the statement's: {e:?}"
    );
    assert!(
        d.get_attestation(&admitted.row_id.hex())
            .await
            .unwrap()
            .is_none(),
        "I2915 nothing stored"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2915_the_weight_column_is_stored_and_read_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2915_the_weight_column_is_stored_and_read_postgres() {
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

/// `[-16, h'nn..']`.
fn digest(n: u8) -> Value {
    Value::Array(vec![Value::Nint(15), Value::Bytes(vec![n; 32])])
}

/// I2924: digests read back as hex, at the mapping.
#[test]
fn i2924_the_mapping_renders_digests_as_hex() {
    let mut row = delegation(None);
    // A score row of the vector family citing two blobs.
    row.family = "evidence:.suite:.kind:.cell:.prefix".into();
    row.row_type = "scores".into();
    row.payload = map(vec![
        ("asserted_at", Value::Uint(5_000)),
        (
            "evidence_refs",
            Value::Array(vec![digest(0x71), digest(0x70)]),
        ),
    ]);
    let a = attestation_of(&row, INGEST_TIER).unwrap();
    assert_eq!(
        a.attestation_envelope["evidence_refs"],
        serde_json::json!([hex::encode([0x71u8; 32]), hex::encode([0x70u8; 32])]),
        "I2924 a sequence of digests is an array of hex, in order"
    );
    // A family's own digest member.
    row.family = ciris_verify_core::namespace_match::family_id("takedown_notice:{basis}");
    row.payload = map(vec![
        ("asserted_at", Value::Uint(5_000)),
        ("content_sha256", digest(0x72)),
    ]);
    let a = attestation_of(&row, INGEST_TIER).unwrap();
    assert_eq!(
        a.attestation_envelope["content_sha256"],
        serde_json::json!(hex::encode([0x72u8; 32])),
        "I2924 a family's digest member is hex"
    );
    // A non-digest member of another family is left as it is.
    row.family = "evidence:.suite:.kind:.cell:.prefix".into();
    row.payload = map(vec![
        ("asserted_at", Value::Uint(5_000)),
        ("content_sha256", digest(0x72)),
    ]);
    let a = attestation_of(&row, INGEST_TIER).unwrap();
    assert!(
        a.attestation_envelope["content_sha256"].is_array(),
        "I2924 only a listed digest member is rendered as hex"
    );
}

/// I2924: the purge derivation follows an edition-2 score's evidence.
async fn purge_body(d: &dyn FederationDirectory) {
    use crate::federation::steward_purge::{human_subject_records, parse_record_id};
    let k = key(164);
    put_statement(d, &key_record(&k, &["user"], 0, None), None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I2924 key record: {e:?}"));
    let blob = [0x7au8; 32];
    let payload = map(vec![
        ("asserted_at", Value::Uint(5_000)),
        ("author", Value::Text(iref(&k))),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        (
            "evidence_refs",
            Value::Array(vec![Value::Array(vec![
                Value::Nint(15),
                Value::Bytes(blob.to_vec()),
            ])]),
        ),
        (
            "dimension",
            Value::Text("evidence:safety_battery:capture:a:b:v1".into()),
        ),
    ]);
    let st = sign_row_statement(
        &k,
        &iref(&k),
        &iref(&k),
        "scores",
        "evidence:.suite:.kind:.cell:.prefix",
        &payload,
        vec![],
    )
    .unwrap();
    let out = put_statement(d, &st, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I2924 a score citing a blob admits: {e:?}"));
    let StatementOutcome::Row { row_id, .. } = out else {
        panic!("I2924: {out:?}");
    };
    let stored = d.get_attestation(&row_id.hex()).await.unwrap().unwrap();
    assert_eq!(
        stored.attestation_envelope["evidence_refs"],
        serde_json::json!([hex::encode(blob)]),
        "I2924 stored as hex"
    );
    let record = parse_record_id(&format!("blob:{}", hex::encode(blob))).unwrap();
    let found = human_subject_records(d, &[record], &Default::default(), false)
        .await
        .unwrap();
    assert!(
        found
            .iter()
            .any(|h| h.subject == iref(&k) && h.reason.contains("person")),
        "I2924 the purge derivation reads the edition-2 score's evidence and names its \
         subject, a person: {found:?}"
    );
    assert!(
        found.iter().all(|h| !h.subject.is_empty()),
        "I2924 not \"no row binds this blob\": {found:?}"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2924_the_purge_derivation_follows_an_edition2_score_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(purge_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2924_the_purge_derivation_follows_an_edition2_score_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(purge_body(&b)).await;
}

/// I2927: the registered shape, read by the matcher and by the stem.
#[test]
fn i2927_the_deadmission_dimension_is_registered() {
    use crate::federation::admission::{is_peer_deadmission_dimension, PEER_DEADMISSION_DIMENSION};
    use ciris_verify_core::namespace_match::{family_id, resolve, Resolved};
    match resolve(PEER_DEADMISSION_DIMENSION) {
        Ok(Resolved::Family { family_id: f, .. }) => assert_eq!(
            f,
            family_id("revocation:{entity_type}:{reason}"),
            "I2927 the de-admission resolves to the revocation family"
        ),
        other => panic!("I2927 {PEER_DEADMISSION_DIMENSION} is refused or open: {other:?}"),
    }
    assert!(is_peer_deadmission_dimension(PEER_DEADMISSION_DIMENSION));
    assert!(
        is_peer_deadmission_dimension("revocation:peer_admission:v1"),
        "I2927 the earlier spelling still reads as a de-admission"
    );
    assert!(!is_peer_deadmission_dimension(
        "revocation:partner:fraud:v1"
    ));
    // The revocation list leaves the peer_admission leaf to its own shape.
    let p = map(vec![
        ("asserted_at", Value::Uint(5_000)),
        ("dimension", Value::Text(PEER_DEADMISSION_DIMENSION.into())),
        ("score", Value::Nint(999_999)),
        ("cohort_scope", Value::Text("self".into())),
    ]);
    super::payloads::check_by_id(
        &family_id("revocation:{entity_type}:{reason}"),
        "scores",
        &p,
    )
    .expect("I2927 a de-admission payload passes the revocation list");
}

/// A node's key record runs a bounded window (Verify: a `node` record states
/// `valid_until`, at most 365 days; one without it is `key_not_valid`).
const NODE_WINDOW_MS: u64 = 30 * 86_400_000;

/// I2927: an edition-2 de-admission is admitted, and the gate reads it.
async fn deadmission_body(d: &dyn FederationDirectory) {
    use crate::federation::admission::{check_peer_deadmission, PEER_DEADMISSION_DIMENSION};
    use ciris_verify_core::namespace_match::family_id;
    let (node, peer) = (key(165), key(166));
    put_statement(
        d,
        &key_record(&node, &["node"], 0, Some(NODE_WINDOW_MS)),
        None,
        INGEST_TIER,
    )
    .await
    .unwrap_or_else(|e| panic!("I2927 node record: {e:?}"));
    put_statement(
        d,
        &key_record(&peer, &["node"], 0, Some(NODE_WINDOW_MS)),
        None,
        INGEST_TIER,
    )
    .await
    .unwrap_or_else(|e| panic!("I2927 peer record: {e:?}"));
    let payload = map(vec![
        ("asserted_at", Value::Uint(5_000)),
        ("author", Value::Text(iref(&node))),
        ("dimension", Value::Text(PEER_DEADMISSION_DIMENSION.into())),
        // -1.0 at the fixed scale: -1 - 999_999.
        ("score", Value::Nint(999_999)),
        ("cohort_scope", Value::Text("self".into())),
    ]);
    let st = sign_row_statement(
        &node,
        &iref(&node),
        &iref(&peer),
        "scores",
        &family_id("revocation:{entity_type}:{reason}"),
        &payload,
        vec![],
    )
    .unwrap();
    let out = put_statement(d, &st, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I2927 an edition-2 de-admission is admitted: {e:?}"));
    let StatementOutcome::Row { row_id, .. } = out else {
        panic!("I2927: {out:?}");
    };
    let stored = d.get_attestation(&row_id.hex()).await.unwrap().unwrap();
    assert_eq!(
        crate::federation::admission::envelope_dimension(&stored.attestation_envelope),
        Some(PEER_DEADMISSION_DIMENSION),
        "I2927 stored under the registered dimension"
    );
    // The gate reads it: the peer's writes are refused on this node.
    let from_peer = crate::federation::tier_ingest::test_support::bare_attestation(
        "i2927-from-peer",
        &iref(&peer),
        &iref(&peer),
        &serde_json::json!({}),
    );
    let e = check_peer_deadmission(d, &from_peer, &iref(&node), chrono::Utc::now())
        .await
        .expect_err("I2927 the de-admitted peer's write is refused");
    assert!(
        e.to_string().contains("de-admitted"),
        "I2927 the de-admission gate answers: {e}"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2927_an_edition2_deadmission_is_admitted_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(deadmission_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2927_an_edition2_deadmission_is_admitted_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(deadmission_body(&b)).await;
}
