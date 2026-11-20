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
//!
//! v62.0.0 (the JSON cut, slice E): the surface a consumer reaches is the
//! edition-2 fixture switch, `federation::edition2::fixture_switch`. A key
//! becomes live by its `key:record` statement (`put_key`), and a row is a
//! signed statement (`statement_of` / `row_of`). The earlier-form helpers
//! (`register_hybrid_key`, `hybrid_pubkeys`, `sign_envelope`) are gone with the
//! JSON doors.

#![cfg(all(feature = "test-anchor", feature = "sqlite"))]

use ciris_persist::federation::edition2::fixture_switch as e2;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::{Backend as _, SqliteBackend};

/// **The #664 witness, edition 2: register, then sign, then admit — all from
/// outside.**
///
/// If `fixture_switch` ever narrows back to `pub(crate)`, this file stops
/// COMPILING rather than failing an assertion, which is the loudest available
/// signal and the right one: a visibility regression is not a runtime
/// condition.
#[tokio::test]
async fn a_consumer_can_register_the_authority_it_signs_with_664() {
    let backend = SqliteBackend::open_in_memory().await.expect("open");
    backend.run_migrations().await.expect("migrations");

    // THE CALL #664 IS ABOUT. `pub(crate)` here and this file does not build.
    let kid = e2::put_key(&backend, "downstream-authority-664", &["user"]).await;
    assert_eq!(kid, e2::kid("downstream-authority-664"));

    let got = FederationDirectory::lookup_public_key(&backend, &kid)
        .await
        .expect("read")
        .expect("the authority a downstream fixture registered must be resolvable");
    assert_eq!(got.key_id, kid);
    assert!(
        !got.pubkey_ed25519_base64.is_empty(),
        "a registered authority must carry the composite's Ed25519 half"
    );
    assert!(
        got.pubkey_ml_dsa_65_base64.is_some(),
        "and its ML-DSA-65 half: a composite key is both or nothing"
    );
}

/// The row-building helpers a consumer needs beside registration: a signed
/// statement whose row the door admits, and whose id the node computes.
#[tokio::test]
async fn a_consumer_can_reach_the_row_signing_helpers_664() {
    let backend = SqliteBackend::open_in_memory().await.expect("open");
    backend.run_migrations().await.expect("migrations");
    let signer = "downstream-signer-664";
    let _ = e2::put_key(&backend, signer, &["user"]).await;

    let _key = e2::signing_key(signer);
    // The earlier-form-shaped row the codec reads (built with the switch off,
    // so the builder hands back the shape, not a mapped row).
    let mut earlier = {
        ciris_persist::federation::tier_ingest::test_support::bare_attestation(
            "dsx-664",
            signer,
            signer,
            &serde_json::json!({
                "dimension": "evidence:safety_battery:capture:a:b:v1",
                "score": 0.75,
                "confidence": 0.9,
            }),
        )
    };
    earlier.attestation_type = "scores".to_owned();
    let statement = e2::statement_of(&earlier, signer);
    assert!(!statement.is_empty(), "a signed statement");
    let stored = e2::put_row(&backend, &earlier, signer).await;
    assert_eq!(stored.attesting_key_id, e2::kid(signer));
    assert_eq!(
        stored.attestation_id,
        e2::rid(&stored),
        "the node computes the id"
    );
    assert!(
        FederationDirectory::get_attestation(&backend, &stored.attestation_id)
            .await
            .expect("read")
            .is_some(),
        "the admitted row is readable by its node-computed id"
    );
}
