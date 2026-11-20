//! v62.0.0 (F0-cp8; CC 2.6.1.7) — **I2899 (and F0-cp10's I2061–I2062): a host artefact's composite is
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
    accord_manifest_v2_message, domain_preimage, signer_standing, verify_accord_manifest_v2,
    verify_domain_composite_via_directory, SignerStanding, SigningDomain,
    ACCORD_MANIFEST_SIGNER_NOT_HOLDER,
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

    // ── I2061 (F0-cp10): an emergency shutdown signed by a PERSON's own
    //    composite key verifies by identity-ref through the directory ──
    let person = e2::put_key(d, "i2061-person", &["user"]).await;
    let cmd = b"I2061: shut down agent X";
    let shutdown = e2::signing_key("i2061-person")
        .sign(&domain_preimage(SigningDomain::EmergencyShutdown, cmd))
        .expect("the person's composite");
    assert_eq!(
        SigningDomain::from_tag("ciris.emergency_shutdown.v1").unwrap(),
        SigningDomain::EmergencyShutdown,
        "I2061"
    );
    let ok = verify_domain_composite_via_directory(
        d,
        SigningDomain::EmergencyShutdown,
        cmd,
        &person,
        &shutdown,
        now_ms(),
    )
    .await
    .unwrap_or_else(|e| panic!("I2061: a person's shutdown verifies: {e}"));
    assert_eq!(ok.identity_ref, person, "I2061: the signer named");
    let e = verify_domain_composite_via_directory(
        d,
        SigningDomain::AgentSystemTask,
        cmd,
        &person,
        &shutdown,
        now_ms(),
    )
    .await
    .expect_err("I2061: not as another domain's");
    assert_eq!(e.token(), VERIFY_COMPOSITE_INVALID, "I2061: {e}");

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

    // ── I2062 (F0-cp10): the signer's standing, on the existing reads ──
    let agent = e2::put_key(d, "i2062-agent", &["agent"]).await;
    let owner = e2::put_key(d, "i2062-owner", &["user"]).await;
    let wa = e2::put_key(d, "i2062-wa", &["user", "wise_authority"]).await;
    let other_agent = e2::put_key(d, "i2062-other-agent", &["agent"]).await;
    super::fixture_occurrence::put_agent_owner_binding(d, "i2062-owner", "i2062-agent", now_ms())
        .await;
    // A WA body (a family) seating `i2062-wa` and a plain member; a second
    // carded key outside it.
    let _ = e2::put_key(d, "i2062-wa-outside", &["user", "wise_authority"]).await;
    let plain = e2::put_key(d, "i2062-plain", &["user"]).await;
    let body = crate::federation::edition2::voices_invariants::found_family(
        d,
        "i2062-wa-body",
        &["i2062-wa", "i2062-plain"],
        "majority",
    )
    .await;
    let wa_body = Some(body.family_key_id.as_str());
    let at = now_ms();
    let st = |who: &str, of: &str, b: Option<&str>| {
        let (who, of, b) = (who.to_owned(), of.to_owned(), b.map(str::to_owned));
        async move {
            signer_standing(d, &who, &of, b.as_deref(), at)
                .await
                .unwrap_or_else(|e| panic!("I2062: standing of {who}: {e}"))
        }
    };
    assert_eq!(
        st(&holder, &agent, wa_body).await,
        SignerStanding::Root,
        "I2062: an accord holder is ROOT"
    );
    assert_eq!(
        st(&wa, &agent, wa_body).await,
        SignerStanding::WiseAuthority,
        "I2062: an active, carded member of the named WA body"
    );
    assert_eq!(
        st(&wa, &agent, None).await,
        SignerStanding::None,
        "I2062: the self-declared card alone is no standing (no WA body named)"
    );
    assert_eq!(
        st(&e2::kid("i2062-wa-outside"), &agent, wa_body).await,
        SignerStanding::None,
        "I2062: a carded key outside the WA body"
    );
    assert_eq!(
        st(&plain, &agent, wa_body).await,
        SignerStanding::None,
        "I2062: a WA-body member without the card"
    );
    assert_eq!(
        st(&owner, &agent, wa_body).await,
        SignerStanding::Owner,
        "I2062: the agent's counted owner"
    );
    assert_eq!(
        st(&owner, &other_agent, wa_body).await,
        SignerStanding::None,
        "I2062: an owner of no other agent"
    );
    assert_eq!(
        st(&person, &agent, wa_body).await,
        SignerStanding::None,
        "I2062: a person with no standing"
    );
    assert_eq!(SignerStanding::WiseAuthority.as_str(), "wise_authority");
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
