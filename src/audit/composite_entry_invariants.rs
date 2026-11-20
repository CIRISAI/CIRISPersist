//! v62.0.0 (F0-cp8; CC 6.1.3, CC 2.6.1.7) — **an audit entry carries ONE
//! composite under its signer's identity-ref**, witnessed on sqlite AND
//! postgres (I2895–I2898; I2894 is the preimage pin in `audit::verify`).
//!
//! RULINGS: "Composite signatures only. There are no standalone component
//! signers." The earlier entry form (a lone Ed25519 over the canonical JSON,
//! `actor_id` the Ed25519 pubkey) is refused by name at both doors
//! (`record_entry`, `try_claim_event`); the Merkle leaf keeps stripping the
//! signature.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_verify_core::transparency::TransparencyLeaf as _;
use ed25519_dalek::Signer as _;

use super::merkle_leaf::AuditLeaf;
use super::service::AuditService;
use super::test_support::{actor, put_actor, seal};
use super::types::{AuditEntry, ChainVerifyOutcome};
use super::verify::{
    canonical_bytes_for_entry, compute_entry_hash, entry_signing_preimage, truncate_to_micros,
};
use super::{Error, GENESIS_PREV_HASH};
use crate::federation::edition2::composite_verify::{
    VERIFY_COMPONENT_SIGNATURE, VERIFY_COMPOSITE_INVALID, VERIFY_NOT_IDENTITY_REF,
    VERIFY_UNKNOWN_KEY,
};
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::FederationDirectory;

/// The actor whose `key:record` is held.
const ACTOR: &str = "f0-cp8-audit-actor";
/// Another held key: its composite is not the actor's.
const OTHER: &str = "f0-cp8-audit-other";
/// Never put.
const ABSENT: &str = "f0-cp8-audit-absent";

fn draft(tenant: &str, seq: i64, prev_hash: Vec<u8>) -> AuditEntry {
    AuditEntry {
        entry_id: uuid::Uuid::new_v4().to_string(),
        sequence_number: seq,
        tenant_id: tenant.to_owned(),
        actor_id: String::new(),
        action_type: "handler_action_task_complete".into(),
        subject_kind: "task".into(),
        subject_id: format!("subj-{seq}"),
        payload: serde_json::json!({"seq": seq}),
        prev_hash,
        entry_hash: vec![],
        recorded_at: truncate_to_micros(chrono::Utc::now()),
        signature: String::new(),
    }
}

/// The earlier entry form: `actor_id` the Ed25519 pubkey, a lone Ed25519
/// over the canonical JSON (signature stripped).
fn earlier_form(tenant: &str, seq: i64, prev_hash: Vec<u8>) -> AuditEntry {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x8C; 32]);
    let mut e = draft(tenant, seq, prev_hash);
    e.actor_id = B64.encode(key.verifying_key().to_bytes());
    e.entry_hash = compute_entry_hash(&e).unwrap().to_vec();
    let canonical = canonical_bytes_for_entry(&e).unwrap();
    e.signature = B64.encode(key.sign(&canonical).to_bytes());
    e
}

/// `entry` re-signed: `actor_id` as given, `signature` the bytes `sig_of`
/// makes from the preimage.
fn resigned(mut e: AuditEntry, actor_id: &str, sig_of: impl Fn(&[u8]) -> Vec<u8>) -> AuditEntry {
    e.actor_id = actor_id.to_owned();
    e.signature = String::new();
    e.entry_hash = compute_entry_hash(&e).unwrap().to_vec();
    let pre = entry_signing_preimage(&e).unwrap();
    e.signature = B64.encode(sig_of(&pre));
    e
}

fn refused_with(what: &str, got: Result<(), Error>, token: &str) {
    match got {
        Err(Error::Signature(m)) => assert!(
            m.starts_with(token),
            "{what}: refused by name ({token}), got {m:?}"
        ),
        other => panic!("{what}: expected Signature({token}…), got {other:?}"),
    }
}

async fn claim<A: AuditService>(audit: &A, e: AuditEntry) -> Result<(), Error> {
    audit
        .try_claim_event(compute_entry_hash(&e).unwrap(), e, "i2896".into())
        .await
        .map(|_| ())
}

async fn body<A: AuditService, D: FederationDirectory + ?Sized>(audit: &A, dir: &D) {
    let held = put_actor(dir, ACTOR).await;
    put_actor(dir, OTHER).await;
    assert_eq!(held, actor(ACTOR), "the fixture's identity-ref");
    let tenant = format!("i2895-{}", uuid::Uuid::new_v4().simple());

    // ── I2895: a composite by the actor's live edition-2 key is recorded,
    //    and the chain walk re-verifies it at its stored instant ──
    let e1 = seal(ACTOR, draft(&tenant, 1, GENESIS_PREV_HASH.to_vec()));
    assert_eq!(e1.actor_id, held, "I2895: the actor is its identity-ref");
    assert_eq!(
        B64.decode(&e1.signature).unwrap().len(),
        ciris_crypto::composite::SIGNATURE_LEN,
        "I2895: ONE composite"
    );
    audit
        .record_entry(e1.clone())
        .await
        .unwrap_or_else(|e| panic!("I2895: a composite entry is recorded: {e}"));
    let walk = audit.verify_chain(&tenant, 1, None).await.unwrap();
    assert!(
        matches!(walk.outcome, ChainVerifyOutcome::Ok),
        "I2895: the walk verifies it: {:?}",
        walk.outcome
    );
    assert_eq!(walk.entries_walked, 1, "I2895");

    // ── I2896: the earlier form — a lone Ed25519 — is refused by name at
    //    both doors, whether its actor is the pubkey or an identity-ref ──
    let next = || draft(&tenant, 2, e1.entry_hash.clone());
    let lone_earlier = earlier_form(&tenant, 2, e1.entry_hash.clone());
    refused_with(
        "I2896 record (earlier form)",
        audit.record_entry(lone_earlier.clone()).await,
        VERIFY_COMPONENT_SIGNATURE,
    );
    refused_with(
        "I2896 claim (earlier form)",
        claim(audit, lone_earlier).await,
        VERIFY_COMPONENT_SIGNATURE,
    );
    let ed = ed25519_dalek::SigningKey::from_bytes(&[0x8D; 32]);
    let lone_under_ref = resigned(next(), &held, |m| ed.sign(m).to_bytes().to_vec());
    refused_with(
        "I2896 record (lone Ed25519 under an identity-ref)",
        audit.record_entry(lone_under_ref).await,
        VERIFY_COMPONENT_SIGNATURE,
    );
    // The composite's own Ed25519 half, alone, is the same refusal.
    let half = resigned(next(), &held, |m| {
        let c = e2::signing_key(ACTOR).sign(m).unwrap();
        c[c.len() - 64..].to_vec()
    });
    refused_with(
        "I2896 record (the composite's Ed25519 half)",
        audit.record_entry(half).await,
        VERIFY_COMPONENT_SIGNATURE,
    );

    // ── I2897: the composite must be the actor's, over THIS preimage, by a
    //    held key named by an identity-ref ──
    let by_other = resigned(next(), &held, |m| e2::signing_key(OTHER).sign(m).unwrap());
    refused_with(
        "I2897 another key's composite",
        audit.record_entry(by_other).await,
        VERIFY_COMPOSITE_INVALID,
    );
    let mut over_json = seal(ACTOR, next());
    let canonical = canonical_bytes_for_entry(&over_json).unwrap();
    over_json.signature = B64.encode(e2::signing_key(ACTOR).sign(&canonical).unwrap());
    refused_with(
        "I2897 a composite over the earlier JSON bytes",
        audit.record_entry(over_json).await,
        VERIFY_COMPOSITE_INVALID,
    );
    refused_with(
        "I2897 an actor whose key:record is not held",
        audit.record_entry(seal(ABSENT, next())).await,
        VERIFY_UNKNOWN_KEY,
    );
    let pubkey_actor = resigned(next(), &B64.encode([7u8; 32]), |m| {
        e2::signing_key(ACTOR).sign(m).unwrap()
    });
    refused_with(
        "I2897 an actor that is not an identity-ref",
        audit.record_entry(pubkey_actor).await,
        VERIFY_NOT_IDENTITY_REF,
    );
    // Nothing refused landed: the next composite still takes seq 2.
    let e2 = seal(ACTOR, next());
    audit
        .try_claim_event(compute_entry_hash(&e2).unwrap(), e2.clone(), "i2897".into())
        .await
        .unwrap_or_else(|e| panic!("I2897: the actor's composite is claimed: {e}"));
    let walk = audit.verify_chain(&tenant, 1, None).await.unwrap();
    assert!(
        matches!(walk.outcome, ChainVerifyOutcome::Ok),
        "I2897: {:?}",
        walk.outcome
    );
    assert_eq!(walk.entries_walked, 2, "I2897: exactly the two composites");

    // ── I2898: the Merkle leaf keeps stripping the signature: a leaf's
    //    bytes are the entry's, whatever its signature ──
    let mut stripped = e2.clone();
    stripped.signature = "c2lnbmF0dXJl".into();
    assert_eq!(
        AuditLeaf::new(e2.clone()).canonical_bytes().unwrap(),
        AuditLeaf::new(stripped).canonical_bytes().unwrap(),
        "I2898: the leaf does not hash the signature"
    );
    let mut no_hash = e2.clone();
    no_hash.entry_hash = vec![];
    no_hash.signature = String::new();
    assert_eq!(
        AuditLeaf::new(e2).canonical_bytes().unwrap(),
        canonical_bytes_for_entry(&no_hash).unwrap(),
        "I2898: the leaf is the entry's canonical JSON, hash and signature stripped"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2895_to_i2898_sqlite() {
    use crate::store::Backend as _;
    let backend = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    backend.run_migrations().await.unwrap();
    let audit = super::sqlite::SqliteAuditBackend::new(backend.conn_handle());
    body(&audit, &backend).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2895_to_i2898_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::dsn() else {
        eprintln!("I2895 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
        return;
    };
    let backend = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    backend.run_migrations().await.unwrap();
    body(&backend, &backend).await;
}
