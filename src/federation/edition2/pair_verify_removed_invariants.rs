//! v62.0.0 (BH-fix1; RULINGS "composite signatures only") — **the quorum
//! counts that verified a SEPARATE Ed25519 + ML-DSA-65 pair** (Verify's
//! `ThresholdSignature`, `verify_threshold_signatures`) now count the
//! edition-2 door's vouched voices only: each voice is ONE composite
//! statement, verified when it arrived.
//!
//! - **I2120** (sqlite AND postgres) — the accord's standing-majority count
//!   (`tier_ingest::standing_majority_signed_by`, read by the accord head
//!   version and the accord roster change): genuine separate pairs from every
//!   standing holder over the change envelope's signing bytes count for
//!   nothing; vouched voices of a strict majority count; a minority, voices
//!   off the standing roster, or a vouch over another envelope do not.
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
use crate::federation::tier_ingest::standing_majority_signed_by;
use crate::federation::types::{Family, FamilyMember, GroupSupersedeProof};
use crate::federation::{malformed_row, Error, FederationDirectory};

/// Standing holders; their names differ within their first 32 bytes (a test
/// signer seeds from them).
const A: &str = "bh1-a-standing-holder";
const B: &str = "bh1-b-standing-holder";
const C: &str = "bh1-c-standing-holder";
/// Never on the standing roster.
const OUTSIDER: &str = "bh1-o-not-a-holder";

fn envelope(tag: &str) -> serde_json::Value {
    serde_json::json!({
        "kind": "ciris.accord_roster_change.v1",
        "tag": tag,
        "members": [A, B, C],
    })
}

/// A proof over `env` carrying GENUINE separate pairs from `signers`, each
/// over the change envelope's signing bytes (the bound form: ML-DSA-65 over
/// `bytes ‖ ed25519_sig`), from the signer's own deterministic component
/// keys.
fn proof_with_pairs(env: &serde_json::Value, signers: &[&str]) -> GroupSupersedeProof {
    // v62.0.0 (VA-steward-purge) — the change envelope's signing bytes are
    // its JCS (CIRISVerify 23.3.2's `accord_family_signing_bytes` was
    // `jcs::canonicalize`, removed in 23.3.3): the same bytes, as setup.
    let bytes =
        ciris_verify_core::jcs::canonicalize(env).expect("the change envelope canonicalizes");
    GroupSupersedeProof {
        prior_persist_row_hash: String::new(),
        change_envelope: env.clone(),
        quorum_signatures: signers
            .iter()
            .map(|s| crate::federation::tier_ingest::test_support::threshold_sign(s, &bytes))
            .collect(),
    }
}

async fn standing(d: &dyn FederationDirectory) {
    let standing: Vec<String> = [A, B, C].iter().map(|s| (*s).to_owned()).collect();
    let env = envelope("I2120");
    let proof = proof_with_pairs(&env, &[A, B, C]);
    assert_eq!(
        proof.quorum_signatures.len(),
        3,
        "I2120: the proof carries a separate pair from every holder"
    );

    // (a) every holder's genuine separate pair, no vouch: nobody signed.
    assert!(
        !standing_majority_signed_by(d, &standing, &proof)
            .await
            .unwrap(),
        "I2120 (a): separate pairs are not counted"
    );
    // (b) the vouched voices of a strict majority count.
    assert!(
        with_quorum_vouch(
            env.clone(),
            &[A, B],
            standing_majority_signed_by(d, &standing, &proof)
        )
        .await
        .unwrap(),
        "I2120 (b): two of three vouched voices are a strict majority"
    );
    // (c) a minority does not, whatever pairs the proof carries.
    assert!(
        !with_quorum_vouch(
            env.clone(),
            &[A],
            standing_majority_signed_by(d, &standing, &proof)
        )
        .await
        .unwrap(),
        "I2120 (c): one vouched voice of three is short"
    );
    // (d) voices off the standing roster count for nothing.
    assert!(
        !with_quorum_vouch(
            env.clone(),
            &[A, OUTSIDER],
            standing_majority_signed_by(d, &standing, &proof)
        )
        .await
        .unwrap(),
        "I2120 (d): an outsider's voice is not a holder's"
    );
    // (e) a vouch over another change envelope vouches nothing here.
    assert!(
        !with_quorum_vouch(
            envelope("another"),
            &[A, B, C],
            standing_majority_signed_by(d, &standing, &proof)
        )
        .await
        .unwrap(),
        "I2120 (e): the vouch names another envelope"
    );
}

/// I2120 on sqlite.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2120_standing_majority_counts_voices_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(standing(&b)).await;
}

/// I2120 on postgres.
#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2120_standing_majority_counts_voices_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(standing(&b)).await;
}

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
