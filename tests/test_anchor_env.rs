//! v38.0.0 (CIRISPersist#738) — the test-anchor suite, in its OWN PROCESS.
//!
//! These tests arm the compile-time-fenced genesis override by mutating the
//! process environment (`CIRIS_TESTING_MODE` / `CIRIS_TEST_TRUST_ROOT*` /
//! `ENVIRONMENT`) — state every roster reader in the crate consumes through
//! `effective_accord_holder_records()`. As lib unit tests they made 21
//! neighbours fail in parallel and pass serially (the shared-state class the
//! v37.0.0 changelog filed): under `cargo test` the arm window collapsed the
//! constitutional roster to one synthetic key for every overlapping test,
//! and a panic inside an armed test leaked the arm for the rest of the run.
//!
//! An integration target is its own process under BOTH runners (`cargo
//! test` and nextest), so the mutation cannot reach the lib's tests; the
//! RAII guard below keeps a panic from leaking the arm within this process;
//! and `genesis::test_anchor_env_hygiene` tripwires any env-mutating test
//! from reappearing under src/.

#![cfg(feature = "test-anchor")]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_persist::federation::genesis::*;
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;

/// v38.0.0 (#738) — the arm is an RAII GUARD, not a call pair: a panicking
/// test used to leak `CIRIS_TESTING_MODE=true` into the remainder of the
/// process, which is how one red turned every later roster reader red. The
/// guard's Drop disarms on every exit path, panic included. (This file is
/// its own process under both `cargo test` and nextest — that isolation is
/// the primary fix; the guard is the belt inside it.)
struct TestAnchor {
    pubkey_b64: String,
}

impl TestAnchor {
    fn arm() -> Self {
        let ed = ed25519_dalek::SigningKey::from_bytes(&[0x5Au8; 32]);
        let pk_b64 = B64.encode(ed.verifying_key().to_bytes());
        std::env::set_var("CIRIS_TESTING_MODE", "true");
        std::env::set_var("CIRIS_TEST_TRUST_ROOT", &pk_b64);
        std::env::remove_var("ENVIRONMENT");
        std::env::remove_var("CIRIS_ENV");
        std::env::remove_var("CIRIS_ENVIRONMENT");
        Self { pubkey_b64: pk_b64 }
    }
}

impl Drop for TestAnchor {
    fn drop(&mut self) {
        std::env::remove_var("CIRIS_TESTING_MODE");
        std::env::remove_var("CIRIS_TEST_TRUST_ROOT");
        std::env::remove_var("CIRIS_TEST_TRUST_ROOT_PQC");
        std::env::remove_var("CIRIS_TEST_TRUST_ROOT_SCRUB");
        std::env::remove_var("CIRIS_TEST_TRUST_ROOT_SCRUB_PQC");
        std::env::remove_var("ENVIRONMENT");
    }
}

/// The #449 repro, fixed: under the armed override the full genesis-seed
/// boot path succeeds against the SWAPPED anchor — the SW holder row is
/// seeded and verified (present == live anchor at n=1), the family's
/// founder seats follow the test roster, and the unseedable baked 2-of-3
/// canonical is skipped instead of bricking the boot.
/// **CIRISPersist#545 — the synthesizer's own output must round-trip
/// through `put_public_key`.** The v22.0.0 regression: the test-anchor
/// genesis emits the honest `SoftwareOnly_TEST` custody marker, and the
/// hardware-attestation policy's serde gate required a non-optional
/// `platform_attestation` — so persist refused its OWN synthesized accord
/// holders with `malformed: missing field platform_attestation`, before
/// any tier logic could honour the marker.
///
/// Nothing here caught it because the genesis tests seed through
/// `seed_genesis_accord_holders` — a privileged path — while every HOST
/// feeds the roster to `put_public_key`. A fixture that reaches past the
/// real gate certifies nothing about it (the AV-77 lesson, again). This
/// is the "does our own output satisfy our own gate?" property, the #541
/// preserve-set≡verified-set check in roster form — and it is the test
/// CIRISServer asked for in #545, verbatim.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn synthesized_accord_holders_round_trip_through_put_public_key_545() {
    let _anchor = TestAnchor::arm();

    let backend = SqliteBackend::open_in_memory().await.unwrap();
    backend.run_migrations().await.unwrap();
    let dir: &dyn ciris_persist::federation::FederationDirectory = &backend;

    let records = effective_accord_holder_records();
    assert!(
        !records.is_empty(),
        "#545: a live test anchor must synthesize a non-empty roster"
    );
    for rec in records.iter().cloned() {
        let key_id = rec.record.key_id.clone();
        dir.put_public_key(rec).await.unwrap_or_else(|e| {
            panic!(
                "#545: put_public_key must ADMIT the synthesizer's own \
                 accord holder {key_id}: {e}"
            )
        });
    }
}

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn test_anchor_boot_seeds_swapped_roster_sqlite() {
    let anchor = TestAnchor::arm();
    let pk_b64 = anchor.pubkey_b64.clone();

    let backend = SqliteBackend::open_in_memory().await.unwrap();
    backend.run_migrations().await.unwrap();
    backend
        .seed_genesis_accord_holders(&effective_accord_holder_records())
        .await
        .expect("seed the SW test-root holder");
    seed_family_and_canonical(&backend)
        .await
        .expect("#449: the genesis-seed boot path must succeed in test mode");

    let dir: &dyn ciris_persist::federation::FederationDirectory = &backend;
    // The SW holder row is live with the override pubkey.
    let row = dir
        .lookup_public_key("test-accord-holder-0")
        .await
        .unwrap()
        .expect("the synthesized test holder is seeded");
    assert_eq!(row.pubkey_ed25519_base64, pk_b64);
    assert_eq!(
        row.identity_type,
        ciris_persist::federation::types::identity_type::ACCORD_HOLDER
    );
    // The baked A1/B1/C1 are NOT seeded (the roster is swapped, not merged).
    let baked_a1 = &accord_holder_genesis_records()[0].record.key_id;
    assert!(dir.lookup_public_key(baked_a1).await.unwrap().is_none());
    // Family seats follow the test roster.
    let fam = dir
        .lookup_family(ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID)
        .await
        .unwrap()
        .expect("family seeded");
    assert_eq!(fam.members.len(), 1);
    assert_eq!(fam.members[0].key_id, "test-accord-holder-0");
    // The baked canonical bake was skipped, not force-inserted.
    assert!(backend.list_canonical_servers().await.unwrap().is_empty());
}

/// Without the runtime flag the feature is inert: the effective roster is
/// the baked trio, byte-identical to a prod build.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn test_anchor_inert_without_runtime_flag() {
    let recs = effective_accord_holder_records();
    assert_eq!(recs.len(), 3, "baked A1/B1/C1 when the mode is unarmed");
    assert_eq!(
        recs[0].record.key_id,
        accord_holder_genesis_records()[0].record.key_id
    );
}

/// The anti-production tripwire (re-checked through verify's shared gate):
/// an explicit prod signal defeats the override even with the test flag +
/// root set — the effective roster stays baked.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn test_anchor_prod_tripwire_defeats_override() {
    let _anchor = TestAnchor::arm();
    std::env::set_var("ENVIRONMENT", "production");
    let recs = effective_accord_holder_records();
    assert_eq!(recs.len(), 3, "prod signal must defeat the test override");
}

/// v17.2.0 (CIRISPersist#451) — the persist-tier END-TO-END proving the
/// full harness test model with REAL crypto and ZERO verification
/// relaxation (per the harness owner's directive):
///
/// 1. arm the override with a SW hybrid root the test holds the private
///    halves of, including the #451 PQC pubkey + self-scrub env halves;
/// 2. a full `Engine` BUILDS in test mode (the #449 repro at Engine
///    tier), seeding a PQC-COMPLETE `test-accord-holder-0` carrying the
///    harness-supplied REAL self-scrub;
/// 3. a node record hybrid-scrubbed by the SW root
///    (`produce_scrubbed_key_record`, the exact server-tier bless path)
///    ADMITS through `register_federation_key` — the always-on
///    `HybridPolicy::Strict` verifies both halves against the seeded row;
/// 4. persist's own `root_binding` CONFIRMS the blessed node, chain
///    terminating at `test-accord-holder-0` — pinning the #451 rooting
///    contract: WITH the env-supplied self-scrub the terminus verifies
///    (without it, persist-side rooting through the placeholder terminus
///    does not confirm; verify-side anchor-membership rooting is
///    unaffected either way).
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn test_anchor_e2e_sw_root_blesses_node_and_roots() {
    use ciris_crypto::{Ed25519Signer, MlDsa65Signer};
    use ciris_verify_core::federation_self_record::{produce_scrubbed_key_record, ScrubTarget};
    use ciris_verify_core::self_at_login::{HybridSigningIdentity, SelfSigner};

    // SW root + node hybrid identities — Boxed and built BEFORE any
    // await (multi-KiB ML-DSA signers on 2 MB test stacks).
    let root = Box::new(HybridSigningIdentity::new(
        "test-accord-holder-0",
        Ed25519Signer::random().unwrap(),
        MlDsa65Signer::new().unwrap(),
    ));
    let node = Box::new(HybridSigningIdentity::new(
        "test-node-1",
        Ed25519Signer::random().unwrap(),
        MlDsa65Signer::new().unwrap(),
    ));
    let root_member = root.directory_member().unwrap();
    let node_member = node.directory_member().unwrap();

    // The HARNESS half of the #451 contract: self-scrub over persist's
    // pinned synthesized envelope (classical + bound PQC, sign_bound).
    //
    // v31.0.0 (CIRISVerify 13.1.0) — through
    // `test_anchor_registration_envelope`, NOT a transcribed literal. This
    // test stood in for CIRISServer's harness by re-writing the envelope by
    // hand, so when 13.1.0 moved the preimage the producer and its own
    // witness moved apart and the terminus stopped rooting. Calling the
    // shared function is what makes this leg a real e2e rather than two
    // copies of a string agreeing with each other.
    let envelope = ciris_persist::federation::genesis::test_anchor_registration_envelope(
        "test-accord-holder-0",
        &root_member.ed25519_public_key_base64,
        root_member.mldsa65_public_key_base64.as_deref(),
    );
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope).unwrap();
    let (scrub_ed, scrub_pqc) = root.sign_bound(&canonical).await.unwrap();

    std::env::set_var("CIRIS_TESTING_MODE", "true");
    std::env::set_var(
        "CIRIS_TEST_TRUST_ROOT",
        &root_member.ed25519_public_key_base64,
    );
    std::env::set_var(
        "CIRIS_TEST_TRUST_ROOT_PQC",
        root_member
            .mldsa65_public_key_base64
            .as_deref()
            .expect("hybrid root has an ML-DSA pubkey"),
    );
    std::env::set_var("CIRIS_TEST_TRUST_ROOT_SCRUB", &scrub_ed);
    std::env::set_var("CIRIS_TEST_TRUST_ROOT_SCRUB_PQC", &scrub_pqc);
    std::env::remove_var("ENVIRONMENT");
    std::env::remove_var("CIRIS_ENV");
    std::env::remove_var("CIRIS_ENVIRONMENT");

    // (2) A full Engine builds in test mode.
    let signer = std::sync::Arc::new(ciris_persist::signing::LocalSigner::from_parts(
        ed25519_dalek::SigningKey::from_bytes(&[0x6Cu8; 32]),
        "test-anchor-e2e-steward".to_string(),
        None,
        None,
    ));
    let engine = ciris_persist::engine::Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("#451: a test-mode Engine must build");

    // The seeded holder is PQC-complete and carries the REAL self-scrub.
    let dir = engine.federation_directory();
    let row = dir
        .lookup_public_key("test-accord-holder-0")
        .await
        .unwrap()
        .expect("test holder seeded");
    assert_eq!(
        row.pubkey_ml_dsa_65_base64.as_deref(),
        root_member.mldsa65_public_key_base64.as_deref(),
        "#451: seeded row must carry the env-supplied ML-DSA pubkey"
    );
    assert!(row.pqc_completed_at.is_some());
    assert_eq!(row.scrub_signature_classical, scrub_ed);
    assert_eq!(row.scrub_signature_pqc.as_deref(), Some(scrub_pqc.as_str()));

    // (3) Node bless: the SW root hybrid-scrubs a node registration —
    // the exact server-tier path (CIRISServer harness test_bless).
    let verify_rec = produce_scrubbed_key_record(
        root.as_ref(),
        ScrubTarget {
            key_id: "test-node-1".into(),
            pubkey_ed25519_base64: node_member.ed25519_public_key_base64.clone(),
            pubkey_ml_dsa_65_base64: node_member
                .mldsa65_public_key_base64
                .clone()
                .expect("hybrid node has an ML-DSA pubkey"),
            identity_type: ciris_persist::federation::types::identity_type::NODE.to_owned(),
            roles: Vec::new(),
        },
        "2026-07-14T00:00:00Z",
        &[],
    )
    .await
    .expect("produce the SW-scrubbed node record");
    // Wire-identical shapes: verify's SignedKeyRecord → persist's.
    let persist_rec: ciris_persist::federation::SignedKeyRecord =
        serde_json::from_value(serde_json::to_value(&verify_rec).unwrap())
            .expect("verify→persist SignedKeyRecord wire round-trip");

    // (4) Admitted under the always-on Strict hybrid gate.
    engine
        .register_federation_key(persist_rec)
        .await
        .expect("#451: the SW-root hybrid scrub must admit under Strict");

    // (5) persist-side rooting CONFIRMS through the verifying terminus.
    // Refutable only when the postgres variant is compiled in — the two
    // cfg arms keep clippy clean in BOTH feature configs (irrefutable-let
    // with postgres off, let-else with it on).
    #[cfg(feature = "postgres")]
    let ciris_persist::engine::BackendDispatch::Sqlite(sq) = engine.backend() else {
        panic!("sqlite engine expected");
    };
    #[cfg(not(feature = "postgres"))]
    let ciris_persist::engine::BackendDispatch::Sqlite(sq) = engine.backend();
    let verdict = ciris_persist::federation::rooting::root_binding(
        &**sq,
        "test-node-1",
        &node_member.ed25519_public_key_base64,
    )
    .await;
    assert!(
        verdict.is_confirmed(),
        "#451: the blessed node must root via persist's own root_binding, got {verdict:?}"
    );
    let chain = verdict.chain().unwrap();
    assert!(chain.terminates_at_steward_bootstrap);
    assert_eq!(
        chain.chain.last().unwrap().key_id,
        "test-accord-holder-0",
        "#451: the chain terminates at the SW test root"
    );
}
