//! v31.4.0 (CIRISPersist#664) — **the fixture surface a consumer can actually
//! reach, proven from OUTSIDE the crate.**
//!
//! This file is an integration test on purpose. `tests/` compiles as a separate
//! crate, so `pub(crate)` is invisible here exactly as it is invisible to
//! CIRISServer, CIRISEdge and CIRISAgent. A unit test inside `src/` cannot prove
//! this property at all — it can reach `pub(crate)` and would pass while every
//! downstream consumer stayed blocked. That is precisely how #664 survived:
//! persist's own fixtures were green throughout.
//!
//! The gap it closes: `cohort::test_support::admit_family` is `pub` and its doc
//! states the precondition that `authority_key_id` MUST already be registered —
//! but `register_hybrid_key` sat behind a `pub(crate)` module. A consumer could
//! **sign** an `AdmitSpec` and could not **register** the authority whose
//! pubkeys that signature verifies against. Fails closed, with no way to open
//! it. #604 records four independent workstreams hitting that wall.
//!
//! Everything here is `#[cfg(feature = "test-anchor")]`-gated in the library, so
//! this file asserts the *test-only* contract, not a production one.

#![cfg(all(feature = "test-anchor", feature = "sqlite"))]

use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::{Backend as _, SqliteBackend};

/// **The #664 witness: register, then sign, then admit — all from outside.**
///
/// If `tier_ingest::test_support` ever narrows back to `pub(crate)`, this file
/// stops COMPILING rather than failing an assertion, which is the loudest
/// available signal and the right one: a visibility regression is not a runtime
/// condition.
#[tokio::test]
async fn a_consumer_can_register_the_authority_it_signs_with_664() {
    let backend = SqliteBackend::open_in_memory().await.expect("open");
    backend.run_migrations().await.expect("migrations");

    // THE CALL #664 IS ABOUT. `pub(crate)` here and this file does not build.
    ciris_persist::federation::tier_ingest::test_support::register_hybrid_key(
        &backend,
        "downstream-authority-664",
    )
    .await;

    let got = FederationDirectory::lookup_public_key(&backend, "downstream-authority-664")
        .await
        .expect("read")
        .expect("the authority a downstream fixture registered must be resolvable");
    assert_eq!(got.key_id, "downstream-authority-664");
    assert!(
        !got.pubkey_ed25519_base64.is_empty(),
        "a registered authority must carry a real Ed25519 pubkey — a fixture \
         signs against these bytes"
    );
    assert!(
        got.pubkey_ml_dsa_65_base64.is_some(),
        "register_hybrid_key must register the PQC leg too, or every hybrid \
         verify a downstream fixture drives fails for the wrong reason"
    );
}

/// The row-building helpers a consumer needs beside registration.
///
/// `seal_row_in_place` is the one that matters most: it stamps the signed
/// instants (#598) AND the seven-member row mirror (#643) AND signs, as ONE
/// step. Persist's own fixtures broke twice this release by hand-rolling the
/// half that omits both, so a consumer reaching for it is reaching for the right
/// thing — and it was unreachable.
#[tokio::test]
async fn a_consumer_can_reach_the_row_sealing_helpers_664() {
    use ciris_persist::federation::tier_ingest::test_support as ts;

    let (ed, pqc) = ts::hybrid_pubkeys("downstream-signer-664");
    assert!(!ed.is_empty(), "deterministic Ed25519 pubkey");
    assert!(pqc.is_some(), "deterministic ML-DSA-65 pubkey");

    // Signing an envelope is the other half of what a fixture needs: a consumer
    // that can register a key but not produce a signature it verifies is no
    // better off than before.
    let envelope = serde_json::json!({ "dimension": "trust:accepts", "id": "dsx-664" });
    let (content_hash, sig_classical, sig_pqc) =
        ts::sign_envelope("downstream-signer-664", &envelope);
    assert!(!content_hash.is_empty(), "content hash");
    assert!(!sig_classical.is_empty(), "classical signature");
    assert!(
        sig_pqc.is_some(),
        "PQC signature — the hybrid pair, not half of it"
    );
}
