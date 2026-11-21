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
//! - **I2121** (a pure rule) — the self-leave (`family_dissolution::
//!   verify_self_leave_signature`, CIRISPersist#956): the leaver's vouched
//!   voice is the authority; another member's voice, no vouch, or a vouch
//!   over another envelope is "the leaver did not sign". It takes no
//!   signature list, so a separate pair cannot be offered at all.
//! - **I2122** (sqlite AND postgres) — a skill import is an edition-2 ROW:
//!   one composite `provenance:skill_import:{source}` statement lands through
//!   the statement door, and the earlier manifest's refusal names
//!   `earlier_form_object` (`door::skill_import_manifest_refusal`, the
//!   refusal `verify_skill_import_manifest_b64` raises; I2123 holds the verb).

use crate::federation::edition2::group::with_quorum_vouch;
use crate::federation::family_dissolution::verify_self_leave_signature;
use crate::federation::types::{Family, FamilyMember};
use crate::federation::{malformed_row, Error, FederationDirectory};

/// Standing holders; their names differ within their first 32 bytes (a test
/// signer seeds from them).
const A: &str = "bh1-a-standing-holder";
const B: &str = "bh1-b-standing-holder";
const C: &str = "bh1-c-standing-holder";
fn household() -> Family {
    let founded_at: chrono::DateTime<chrono::Utc> =
        "2020-01-01T00:00:00Z".parse().expect("a pinned instant");
    Family {
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        family_key_id: "bh1-household".to_owned(),
        family_name: "household".to_owned(),
        members: [A, B, C]
            .iter()
            .map(|k| FamilyMember {
                key_id: (*k).to_owned(),
                joined_at: founded_at,
                role: None,
            })
            .collect(),
        founded_at,
        consensus_protocol: "quorum:2/3".to_owned(),
        consensus_protocol_entrenched: false,
        dissolved_at: None,
        persist_row_hash: String::new(),
    }
}

fn leave_envelope(tag: &str) -> serde_json::Value {
    serde_json::json!({
        "tag": tag,
        "supersedes": { "prior_member_key_ids": [A, B, C] },
    })
}

fn did_not_sign(r: Result<(), Error>, what: &str) {
    match r {
        Err(Error::InvalidArgument(m)) => {
            assert!(m.contains("the leaver did not sign"), "I2121 {what}: {m}");
        }
        other => panic!("I2121 {what}: refused as unsigned, not {other:?}"),
    }
}

/// I2121 — the self-leave's authority is the leaver's vouched voice.
#[tokio::test]
async fn i2121_a_self_leave_is_the_leavers_vouched_voice() {
    let held = household();
    let env = leave_envelope("I2121");
    with_quorum_vouch(env.clone(), &[C], async {
        verify_self_leave_signature(&held, &env, C)
    })
    .await
    .unwrap_or_else(|e| panic!("I2121: carol's own voice is the authority: {e:?}"));
    did_not_sign(
        with_quorum_vouch(env.clone(), &[A, B], async {
            verify_self_leave_signature(&held, &env, C)
        })
        .await,
        "(another member's voices)",
    );
    did_not_sign(verify_self_leave_signature(&held, &env, C), "(no vouch)");
    did_not_sign(
        with_quorum_vouch(leave_envelope("another"), &[C], async {
            verify_self_leave_signature(&held, &env, C)
        })
        .await,
        "(a vouch over another envelope)",
    );
}

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
