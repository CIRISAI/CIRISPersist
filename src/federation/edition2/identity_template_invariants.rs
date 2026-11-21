//! v62.0.0 (BH-fix3; CC 2.6.1.7) — **I2125: an identity template is signed by
//! an accord holder, in its own domain**, witnessed on sqlite AND postgres
//! (the preimage layout is I2124, the unit test in `signing_domain`).
//!
//! - a holder of the genesis bundle in force signs ONE composite over
//!   `domain_preimage("ciris.identity_template.v1", digest)`; it verifies;
//! - a live key that is not a holder is refused
//!   `accord_manifest_signer_not_holder`, before its signature is read;
//! - a holder's composite made in `ciris.accord_manifest.v2` does not verify
//!   as a template, and a template signature does not verify as an accord
//!   manifest (domain separation, both ways);
//! - a digest that is not 32 bytes is refused before anything is read.

use super::composite_verify::{now_ms, VERIFY_COMPOSITE_INVALID};
use super::fixture_genesis;
use super::fixture_switch as e2;
use super::signing_domain::{
    accord_manifest_v2_message, domain_preimage, identity_template_v1_message,
    verify_accord_manifest_v2, verify_identity_template_v1, SigningDomain,
    ACCORD_MANIFEST_SIGNER_NOT_HOLDER,
};
use crate::federation::{Error, FederationDirectory};

/// Never a holder: a live `user` key.
const NOT_HOLDER: &str = "i2125-not-an-accord-holder";

fn composite_invalid(r: Result<(), Error>, what: &str) {
    match r {
        Err(Error::SignatureInvalid(m)) => {
            assert!(m.starts_with(VERIFY_COMPOSITE_INVALID), "I2125 {what}: {m}");
        }
        other => panic!("I2125 {what}: refused as an invalid composite, got {other:?}"),
    }
}

async fn body(d: &dyn FederationDirectory) {
    fixture_genesis::install_v2(d)
        .await
        .expect("I2125: the test ceremony installs");
    let c = fixture_genesis::bundle_v2();
    let holder = c.holder_identity_ref(0).to_owned();
    let hex = "cd".repeat(32);
    let digest = identity_template_v1_message(&hex, 2048, &holder).unwrap();
    let sig = c
        .holder_key(0)
        .sign(&domain_preimage(SigningDomain::IdentityTemplate, &digest))
        .expect("holder composite");

    // A holder's template signature verifies.
    verify_identity_template_v1(d, &digest, &holder, &sig, now_ms())
        .await
        .unwrap_or_else(|e| panic!("I2125: a holder's template signature verifies: {e}"));

    // A live non-holder is refused by name.
    let who = e2::put_key(d, NOT_HOLDER, &["user"]).await;
    let theirs = identity_template_v1_message(&hex, 2048, &who).unwrap();
    let their_sig = e2::signing_key(NOT_HOLDER)
        .sign(&domain_preimage(SigningDomain::IdentityTemplate, &theirs))
        .expect("composite sign");
    match verify_identity_template_v1(d, &theirs, &who, &their_sig, now_ms()).await {
        Err(Error::MalformedRow { reason, plane, .. }) => {
            assert_eq!(reason, ACCORD_MANIFEST_SIGNER_NOT_HOLDER, "I2125");
            assert_eq!(plane, "identity_template", "I2125: the plane");
        }
        other => panic!("I2125: a non-holder is refused by name: {other:?}"),
    }

    // Domain separation: the holder's composite over the SAME digest, made
    // in the accord manifest's domain, is not a template signature.
    let accord_domain_sig = c
        .holder_key(0)
        .sign(&domain_preimage(SigningDomain::AccordManifest, &digest))
        .expect("holder composite");
    composite_invalid(
        verify_identity_template_v1(d, &digest, &holder, &accord_domain_sig, now_ms()).await,
        "(an accord-manifest-domain signature)",
    );
    // And the other way: a template-domain signature over the accord
    // manifest's message is not an accord manifest signature.
    let accord_msg = accord_manifest_v2_message(&hex, 2048, &holder).unwrap();
    let template_sig_over_accord = c
        .holder_key(0)
        .sign(&domain_preimage(
            SigningDomain::IdentityTemplate,
            &accord_msg,
        ))
        .expect("holder composite");
    composite_invalid(
        verify_accord_manifest_v2(d, &hex, 2048, &holder, &template_sig_over_accord, now_ms())
            .await,
        "(a template-domain signature as an accord manifest)",
    );
    // Another holder named for holder 0's signature.
    composite_invalid(
        verify_identity_template_v1(d, &digest, c.holder_identity_ref(1), &sig, now_ms()).await,
        "(another holder)",
    );

    // A digest that is not 32 bytes.
    for bad in [&digest[..31], &[0u8; 33][..], &[][..]] {
        match verify_identity_template_v1(d, bad, &holder, &sig, now_ms()).await {
            Err(Error::InvalidArgument(m)) => {
                assert!(
                    m.contains("must be 32 bytes"),
                    "I2125 ({} bytes): {m}",
                    bad.len()
                );
            }
            other => panic!("I2125 ({} bytes): refused, got {other:?}", bad.len()),
        }
    }
}

/// I2125 on sqlite.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2125_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

/// I2125 on postgres.
#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2125_postgres() {
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
