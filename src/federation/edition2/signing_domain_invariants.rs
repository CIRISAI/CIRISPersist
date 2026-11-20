//! v62.0.0 (F0-cp8; CC 2.6.1.7) — **I2899: a host artefact's composite is
//! signed and verified in ONE registered domain**, witnessed on sqlite AND
//! postgres (the registry/framing leg is the unit test in `signing_domain`).
//!
//! - a LocalSigner's composite over `domain_preimage(d, m)` verifies under its
//!   identity-ref in `d`, and in no other domain, and not as a raw signature
//!   over `m`;
//! - an accord manifest (v2) signed by a holder of the genesis bundle in force
//!   verifies; a live key that is not a holder is refused
//!   `accord_manifest_signer_not_holder`; a holder's composite for another
//!   signer_identity, or in another domain, is refused.

use super::composite_verify::{
    now_ms, verify_composite_via_directory, VERIFY_COMPONENT_SIGNATURE, VERIFY_COMPOSITE_INVALID,
};
use super::fixture_genesis;
use super::fixture_switch as e2;
use super::signing_domain::{
    accord_manifest_v2_message, domain_preimage, verify_accord_manifest_v2,
    verify_domain_composite_via_directory, SigningDomain, ACCORD_MANIFEST_SIGNER_NOT_HOLDER,
};
use crate::federation::{Error, FederationDirectory};

fn composite_signer(seed: u8) -> std::sync::Arc<crate::signing::LocalSigner> {
    use ciris_keyring::MlDsa65SoftwareSigner;
    let pqc = MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], "i2899-pqc")
        .expect("seed bytes");
    let pqc: std::sync::Arc<dyn ciris_keyring::PqcSigner> = std::sync::Arc::new(pqc);
    std::sync::Arc::new(crate::signing::LocalSigner::from_parts(
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
        "i2899-signer".to_string(),
        Some(pqc),
        Some("i2899-pqc".to_string()),
    ))
}

async fn body(d: &dyn FederationDirectory) {
    // ── the domain leg: the producer `Engine.sign_composite` uses ──
    let signer = composite_signer(0x99);
    let who = e2::put_key_for_signer(d, &signer, &["user"]).await;
    assert_eq!(who, signer.federation_id().await, "I2899: its identity-ref");
    let m = b"I2899: a system task's bytes";
    let sig = signer
        .sign_composite(&domain_preimage(SigningDomain::AgentSystemTask, m))
        .await
        .expect("I2899: the composite signs");
    verify_domain_composite_via_directory(
        d,
        SigningDomain::AgentSystemTask,
        m,
        &who,
        &sig,
        now_ms(),
    )
    .await
    .unwrap_or_else(|e| panic!("I2899: verifies in its own domain: {e}"));
    for other in SigningDomain::ALL
        .into_iter()
        .filter(|x| *x != SigningDomain::AgentSystemTask)
    {
        let e = verify_domain_composite_via_directory(d, other, m, &who, &sig, now_ms())
            .await
            .expect_err("I2899: no other domain admits it");
        assert_eq!(e.token(), VERIFY_COMPOSITE_INVALID, "I2899 {other:?}: {e}");
    }
    let e = verify_composite_via_directory(d, m, &who, &sig, now_ms())
        .await
        .expect_err("I2899: not a raw signature over the message");
    assert_eq!(e.token(), VERIFY_COMPOSITE_INVALID, "I2899 raw: {e}");
    let lone = &sig[sig.len() - 64..];
    let e = verify_domain_composite_via_directory(
        d,
        SigningDomain::AgentSystemTask,
        m,
        &who,
        lone,
        now_ms(),
    )
    .await
    .expect_err("I2899: a lone Ed25519 half");
    assert_eq!(e.token(), VERIFY_COMPONENT_SIGNATURE, "I2899 lone: {e}");

    // ── the accord manifest leg (v2): the holder check is in the verify ──
    fixture_genesis::install_v2(d)
        .await
        .expect("I2899: the test ceremony installs");
    let c = fixture_genesis::bundle_v2();
    let holder = c.holder_identity_ref(0).to_owned();
    let hex = "ab".repeat(32);
    let msg = accord_manifest_v2_message(&hex, 4096, &holder).unwrap();
    let holder_sig = c
        .holder_key(0)
        .sign(&domain_preimage(SigningDomain::AccordManifest, &msg))
        .expect("holder composite");
    verify_accord_manifest_v2(d, &hex, 4096, &holder, &holder_sig, now_ms())
        .await
        .unwrap_or_else(|e| panic!("I2899: a holder's manifest signature verifies: {e}"));

    // a live key that is not a holder
    let not_holder_msg = accord_manifest_v2_message(&hex, 4096, &who).unwrap();
    let not_holder_sig = signer
        .sign_composite(&domain_preimage(
            SigningDomain::AccordManifest,
            &not_holder_msg,
        ))
        .await
        .unwrap();
    match verify_accord_manifest_v2(d, &hex, 4096, &who, &not_holder_sig, now_ms()).await {
        Err(Error::MalformedRow { reason, .. }) => {
            assert_eq!(reason, ACCORD_MANIFEST_SIGNER_NOT_HOLDER, "I2899");
        }
        other => panic!("I2899: a non-holder is refused by name: {other:?}"),
    }

    // holder 0's composite offered for holder 1, a changed size, another domain
    let holder1 = c.holder_identity_ref(1).to_owned();
    for (what, size, signer_identity, sig) in [
        ("another holder", 4096, holder1.as_str(), holder_sig.clone()),
        ("another size", 4097, holder.as_str(), holder_sig.clone()),
        (
            "another domain",
            4096,
            holder.as_str(),
            c.holder_key(0)
                .sign(&domain_preimage(SigningDomain::AuditEntry, &msg))
                .unwrap(),
        ),
    ] {
        match verify_accord_manifest_v2(d, &hex, size, signer_identity, &sig, now_ms()).await {
            Err(Error::SignatureInvalid(m)) => {
                assert!(m.starts_with(VERIFY_COMPOSITE_INVALID), "I2899 {what}: {m}");
            }
            other => panic!("I2899 {what}: refused, got {other:?}"),
        }
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2899_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2899_postgres() {
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
