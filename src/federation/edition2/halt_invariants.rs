//! **I2103** (the halt door) and **I2104** (the invocation dedup), v62.0.0
//! JSON-cut slice A; CC 4.2.1.1.
//!
//! - I2103, against CIRISVerify 23.2.0's `accord_halt_v1.json` (vendored at
//!   `tests/vectors/verify_v23/accord_halt/`, SHA-256 pinned):
//!   - each of the four invocations reads `valid`, with the vector's row id;
//!   - each refusal reads `refused:{the vector's token}`, `iss_not_holder`
//!     among them. KNOWN DIVERGENCE, TODO(verify-23.3-halt): v1's
//!     `not_a_holder` (a key the roster does not place) is Verify 23.3.0's
//!     corrected `waiting:kid`, and persist answers that;
//!   - with no bundle in force held, every invocation reads `waiting:bundle`;
//!   - at the store door (sqlite + postgres): ONE holder's constitutional
//!     halt latches the accord's active halt, no count; a re-put is
//!     idempotent; `iss_not_holder` is refused by name; a key the roster
//!     does not place waits (retryable); `put_statement` waits on the
//!     bundle (no roster in force is held before slice C).
//! - I2104, both backends: an invocation repeating a held invocation's
//!   `invocation_id`, or its `nonce`, within that one's `valid_until` is
//!   `accord_invocation_replayed`; past it, it is admitted.
//!
//! TODO(verify-23.3-pin): replay `accord_halt_v2.json` (lifecycles and
//! latch sequences included) at slice C's pin. The v1 `lifecycles` and
//! `latch` sets are not replayed here: TODO(cut-a-halt-lifecycle).

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;
use serde_json::Value as J;
use sha2::Digest as _;

use super::door_invariants::fixture::{iref, key, map};
use super::halt::{read_invocation, HaltReading, HaltRoster, FAMILY_CONSTITUTIONAL};

const FILE: &str =
    include_str!("../../../tests/vectors/verify_v23/accord_halt/accord_halt_v1.json");
const FILE_SHA256: &str = "11d2fd2f0c4631870e917e7a6b53dddc6ec76c5e22e5d35b5c30e1101db65df6";
const ACCORD: &str = "humanity-accord";

fn vectors() -> J {
    serde_json::from_str(FILE).unwrap()
}

fn roster(v: &J) -> HaltRoster {
    let r = &v["roster"];
    let bundle: [u8; 32] = hex::decode(r["bundle_object_id_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let holders = r["holders"].as_array().unwrap().iter().map(|h| {
        let n = u8::try_from(h["key_seed"].as_u64().unwrap()).unwrap();
        (
            h["iss"].as_str().unwrap().to_owned(),
            key(n).public_key().clone(),
        )
    });
    HaltRoster::new(
        r["accord_root"].as_str().unwrap(),
        bundle,
        holders,
        r["halt_fuse_secs"]
            .as_u64()
            .map(|s| u32::try_from(s).unwrap()),
    )
}

fn statement(c: &J) -> Vec<u8> {
    hex::decode(c["statement"]["statement_hex"].as_str().unwrap()).unwrap()
}

#[test]
fn i2103_the_vector_file_is_pinned() {
    assert_eq!(
        hex::encode(sha2::Sha256::digest(FILE.as_bytes())),
        FILE_SHA256,
        "I2103: accord_halt_v1.json is Verify 23.2.0's, byte for byte"
    );
}

#[test]
fn i2103_invocations_replay() {
    let v = vectors();
    let r = roster(&v);
    for c in v["invocations"].as_array().unwrap() {
        let got = read_invocation(&statement(c), Some(&r));
        let HaltReading::Valid(inv) = &got else {
            panic!("I2103 {}: {}", c["id"], got.token());
        };
        assert_eq!(
            hex::encode(inv.row_id),
            c["row_id_hex"].as_str().unwrap(),
            "I2103 {} row id",
            c["id"]
        );
        // No bundle in force held: it waits on the bundle.
        assert_eq!(
            read_invocation(&statement(c), None).token(),
            "waiting:bundle",
            "I2103 {}",
            c["id"]
        );
    }
}

#[test]
fn i2103_refusals_replay() {
    let v = vectors();
    let r = roster(&v);
    let cases = v["invocation_refusals"].as_array().unwrap();
    assert_eq!(cases.len(), 14, "I2103: every refusal is replayed");
    for c in cases {
        let expect = c["expect"].as_str().unwrap();
        let want = match expect {
            // TODO(verify-23.3-halt): v1's token; 23.3.0 corrected it.
            "not_a_holder" => "waiting:kid".to_owned(),
            t => format!("refused:{t}"),
        };
        assert_eq!(
            read_invocation(&statement(c), Some(&r)).token(),
            want,
            "I2103 {}",
            c["id"]
        );
    }
}

/// A constitutional halt by `k` (a holder of the vector roster).
fn halt(k: &CompositeSigningKey, id: &str, nonce: u8, at: u64, until: u64) -> Vec<u8> {
    let m = map(vec![
        ("accord_root", Value::Text(ACCORD.into())),
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("invocation_id", Value::Text(id.into())),
        ("nonce", Value::Bytes(vec![nonce; 32])),
        ("valid_until", Value::Uint(until)),
    ]);
    sign_row_statement(
        k,
        &iref(k),
        ACCORD,
        "scores",
        FAMILY_CONSTITUTIONAL,
        &m,
        vec![],
    )
    .unwrap()
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) async fn body(d: &dyn crate::federation::FederationDirectory) {
    use super::halt::put_invocation;
    use super::ingest::{put_statement, INGEST_TIER};
    use crate::federation::{malformed_row, Error};
    let reason = |e: &Error| match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    };
    let v = vectors();
    let r = roster(&v);
    let a1 = statement(&v["invocations"][0]);
    // No roster in force is held at the store door: it waits.
    let e = put_statement(d, &a1, None, INGEST_TIER).await.unwrap_err();
    assert_eq!(
        e.kind(),
        "federation_attester_key_unknown",
        "I2103 waits on the bundle"
    );
    // One holder's statement latches.
    let out = put_invocation(d, &a1, Some(&r)).await.unwrap();
    assert!(out.new && out.latched, "I2103 latches");
    let active = d
        .get_active_halt(ACCORD)
        .await
        .unwrap()
        .expect("I2103 active halt");
    assert_eq!(
        active.active_halt_id,
        hex::encode(out.invocation.row_id),
        "I2103"
    );
    let again = put_invocation(d, &a1, Some(&r)).await.unwrap();
    assert!(!again.new, "I2103 idempotent");
    // iss_not_holder, by name; a key the roster does not place waits.
    let by_id = |id: &str| {
        v["invocation_refusals"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .map(statement)
            .unwrap()
    };
    let e = put_invocation(d, &by_id("iss_of_another_holder"), Some(&r))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), malformed_row::ISS_NOT_HOLDER, "I2103");
    let e = put_invocation(d, &by_id("outsider_halt"), Some(&r))
        .await
        .unwrap_err();
    assert_eq!(
        e.kind(),
        "federation_attester_key_unknown",
        "I2103 unknown kid waits"
    );
    let e = put_invocation(d, &by_id("nonce_31_bytes"), Some(&r))
        .await
        .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::ACCORD_INVOCATION_INVALID,
        "I2103"
    );

    // I2104: the dedup.
    let b1 = key(2);
    let held = halt(&b1, "halt-dedup", 0x21, 2_000_000, 3_000_000);
    put_invocation(d, &held, Some(&r))
        .await
        .expect("I2104 first");
    for (why, st) in [
        (
            "same invocation_id",
            halt(&b1, "halt-dedup", 0x22, 2_500_000, 3_500_000),
        ),
        (
            "same nonce",
            halt(&b1, "halt-other", 0x21, 2_500_000, 3_500_000),
        ),
        (
            "same id, another holder",
            halt(&key(3), "halt-dedup", 0x23, 2_500_000, 3_500_000),
        ),
    ] {
        let e = put_invocation(d, &st, Some(&r)).await.unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::ACCORD_INVOCATION_REPLAYED,
            "I2104 {why}"
        );
    }
    // Past the held one's valid_until, the id may be used again.
    put_invocation(
        d,
        &halt(&b1, "halt-dedup", 0x24, 3_000_001, 4_000_000),
        Some(&r),
    )
    .await
    .expect("I2104 after valid_until");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2103_i2104_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2103_i2104_postgres() {
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
