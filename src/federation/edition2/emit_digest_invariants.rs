//! **I2925** (v62.0.0, wave P1e; applies on cut B): the emit side states
//! every digest member the mapping reads back as hex, so a round trip of a
//! family-level digest is the identity.
//!
//! - `payload_from_envelope` takes the family id and states every member
//!   `payloads::is_digest_member` names for it (hex → `[-16, bstr32]`):
//!   `content_sha256` (takedown), `chunk_root` (delivery receipt),
//!   `at_rest_sha256` (key grant), `unit` (admission), `build_manifest_hash`
//!   (occurrence), `amendment_digest` and `call_fingerprint`. A family that
//!   does not list a member keeps it as text.
//! - Round trip, pure: a delivery receipt's `chunk_root` goes envelope →
//!   `payload_from_envelope` → signed statement → `admit_row` →
//!   `attestation_of`, and reads back as the same hex.
//! - **I3994** (CC rc21 member homes): the emit side states an amendment's
//!   `authorized_by` / `evidence_refs` under `refs.also.cites` (one row,
//!   deduplicated) and a response's `references_attestation_id` under
//!   `refs.answers`, even though every producer's `drop` list names
//!   `references_attestation_id`; the payloads pass the door's lists.
//! - Round trip, store-backed (sqlite and postgres): a
//!   `deferral:response:approved` emitted from its envelope, put through
//!   `put_statement` and read back from the store, carries the same hex for
//!   `amendment_digest` and `call_fingerprint`.

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::sign_row_statement;
use ciris_verify_core::namespace_match::family_id;

use super::door::admit_row;
use super::door_invariants::fixture::*;
use super::emit::payload_from_envelope;
use super::ingest::{attestation_of, put_statement, StatementOutcome, INGEST_TIER};
use super::liveness::HeldKeys;
use super::names::names_of;
use crate::federation::FederationDirectory;

fn hex_of(n: u8) -> String {
    hex::encode([n; 32])
}

fn is_digest(v: Option<&Value>, n: u8) -> bool {
    matches!(
        v.and_then(Value::as_array),
        Some([alg, b]) if alg.as_i64() == Some(-16) && b.as_bytes() == Some(&[n; 32][..])
    )
}

/// I2925: the emit side states each family's digest members.
#[test]
fn i2925_the_emit_side_states_every_family_digest() {
    for (pattern, member) in [
        ("takedown_notice:{basis}", "content_sha256"),
        ("delivery_receipt:{stream_id}", "chunk_root"),
        ("key_grant:{axis}", "at_rest_sha256"),
        ("admission:unit", "unit"),
        ("identity:occurrence", "build_manifest_hash"),
        ("identity_amendment", "amendment_digest"),
        ("deferral:response:{outcome}", "call_fingerprint"),
    ] {
        let env = serde_json::json!({ member: hex_of(0x41) });
        let p = payload_from_envelope(&env, &family_id(pattern), 7, None, &[])
            .unwrap_or_else(|e| panic!("I2925 {pattern}.{member}: {e:?}"));
        assert!(
            is_digest(p.get_text(member), 0x41),
            "I2925 {pattern}.{member} is stated as a hash digest: {p:?}"
        );
    }
    // A family that does not list the member keeps it as text.
    let env = serde_json::json!({ "chunk_root": hex_of(0x41) });
    let p = payload_from_envelope(&env, "consent:state:.state", 7, None, &[]).unwrap();
    assert_eq!(
        p.get_text("chunk_root").and_then(Value::as_text),
        Some(hex_of(0x41).as_str()),
        "I2925 only a listed member is a digest"
    );
    // A sequence keeps its order.
    let env = serde_json::json!({ "evidence_refs": [hex_of(0x52), hex_of(0x51)] });
    let p = payload_from_envelope(&env, "consent:state:.state", 7, None, &[]).unwrap();
    let a = p
        .get_text("evidence_refs")
        .and_then(Value::as_array)
        .unwrap();
    assert!(
        is_digest(a.first(), 0x52) && is_digest(a.get(1), 0x51),
        "I2925 evidence_refs is a sequence, in the envelope's order"
    );
}

/// I2925: a delivery receipt's `chunk_root` round-trips, pure.
#[test]
fn i2925_a_family_digest_round_trips_through_the_door() {
    let k = key(220);
    let mut keys = HeldKeys::new();
    keys.insert_record(key_record(&k, &["user"], 0, None));
    let family = family_id("delivery_receipt:{stream_id}");
    let env = serde_json::json!({
        "dimension": "delivery_receipt:s-1:v1",
        "stream_id": "s-1",
        "epoch": 2,
        "k": 17,
        "chunk_root": hex_of(0x43),
    });
    let payload =
        payload_from_envelope(&env, &family, 5_000, Some(iref(&k).as_str()), &[]).unwrap();
    let st = sign_row_statement(
        &k,
        &iref(&k),
        &iref(&k),
        "scores",
        &family,
        &payload,
        vec![],
    )
    .unwrap();
    let admitted = admit_row(&st, &keys, None, SelectContext::default())
        .unwrap_or_else(|e| panic!("I2925 the emitted receipt admits: {e:?}"));
    let a = attestation_of(&admitted, INGEST_TIER).unwrap();
    assert_eq!(
        a.attestation_envelope["chunk_root"],
        serde_json::json!(hex_of(0x43)),
        "I2925 emit → door → attestation_of: the same hex"
    );
}

async fn body(d: &dyn FederationDirectory) {
    let k = key(221);
    put_statement(d, &key_record(&k, &["user"], 0, None), None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I2925 key record: {e:?}"));
    let family = family_id("deferral:response:{outcome}");
    let env = serde_json::json!({
        "dimension": "deferral:response:approved:v1",
        "deferral_id": "d-1",
        // rc21: the request answered, stated under refs.answers on emit.
        "references_attestation_id": hex_of(0x4a),
        "amendment_digest": hex_of(0x44),
        "call_fingerprint": hex_of(0x45),
    });
    let payload =
        payload_from_envelope(&env, &family, 5_000, Some(iref(&k).as_str()), &[]).unwrap();
    let st = sign_row_statement(
        &k,
        &iref(&k),
        &iref(&k),
        "scores",
        &family,
        &payload,
        vec![],
    )
    .unwrap();
    let out = put_statement(d, &st, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I2925 the emitted approval admits: {e:?}"));
    let StatementOutcome::Row { row_id, .. } = out else {
        panic!("I2925: {out:?}");
    };
    let stored = d.get_attestation(&row_id.hex()).await.unwrap().unwrap();
    for (member, n) in [("amendment_digest", 0x44), ("call_fingerprint", 0x45)] {
        assert_eq!(
            stored.attestation_envelope[member],
            serde_json::json!(hex_of(n)),
            "I2925 {member}: emit → door → store → the same hex"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2925_an_emitted_digest_round_trips_through_the_store_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2925_an_emitted_digest_round_trips_through_the_store_postgres() {
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

/// I3994: the earlier members that name a row are stated under `refs`.
#[test]
fn i3994_the_emit_side_states_row_names_under_refs() {
    use super::payloads::check_by_id;
    let ia = family_id("identity_amendment");
    let env = serde_json::json!({
        "dimension": "identity_amendment:v1",
        "amendment_digest": hex_of(0x46),
        "authorized_by": hex_of(0x47),
        "evidence_refs": [hex_of(0x47)],
    });
    let p =
        payload_from_envelope(&env, &ia, 7, Some("me"), &["references_attestation_id"]).unwrap();
    assert!(p.get_text("authorized_by").is_none() && p.get_text("evidence_refs").is_none());
    let names = names_of(&p).unwrap();
    let cites: Vec<_> = names.iter().filter(|n| n.role == "also:cites").collect();
    assert_eq!(
        cites.len(),
        1,
        "I3994 one approval, deduplicated: {names:?}"
    );
    assert_eq!(cites[0].row.0, [0x47; 32]);
    let p = super::emit::with_member(
        p,
        "author",
        Value::Text(super::door_invariants::fixture::iref(&key(222))),
    )
    .unwrap();
    check_by_id(&ia, "scores", &p).expect("I3994 the amendment passes its list");

    let dr = family_id("deferral:response:{outcome}");
    let env = serde_json::json!({
        "dimension": "deferral:response:approved:v1",
        "deferral_id": "d-1",
        "references_attestation_id": hex_of(0x48),
        "call_fingerprint": hex_of(0x49),
    });
    let p =
        payload_from_envelope(&env, &dr, 7, Some("me"), &["references_attestation_id"]).unwrap();
    let names = names_of(&p).unwrap();
    assert!(
        names
            .iter()
            .any(|n| n.role == "answers" && n.row.0 == [0x48; 32]),
        "I3994 the request under refs.answers: {names:?}"
    );
    assert!(
        names.iter().all(|n| n.role != "target"),
        "I3994 never refs.target"
    );
    let p = super::emit::with_member(
        p,
        "author",
        Value::Text(super::door_invariants::fixture::iref(&key(222))),
    )
    .unwrap();
    check_by_id(&dr, "scores", &p).expect("I3994 the response passes its list");
    // A malformed row id is refused, never stated.
    let bad = serde_json::json!({ "references_attestation_id": "not-a-row-id" });
    assert!(
        payload_from_envelope(&bad, &dr, 7, None, &[]).is_err(),
        "I3994 refused"
    );
}
