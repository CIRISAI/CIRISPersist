//! v23.1.0 (CIRISPersist#554) — the test that feeds persist a **real captured
//! YubiKey custody attestation** and asserts it is ADMITTED.
//!
//! # Why this file exists
//!
//! Every accord-holder fixture in this crate used *synthesized* evidence
//! (`hardware_attestation::test_support::fresh_accord_holder_evidence` — an
//! Android-Strongbox blob shaped to satisfy the gate). That is exactly why
//! CIRISPersist#545 and #554 both reached a real ceremony before anyone
//! noticed: **no test had ever fed persist the evidence a real device
//! produces.** A gate proven only against evidence written to satisfy it is
//! not proven at all.
//!
//! The fixture is the A1 holder record lifted verbatim out of the production
//! genesis bundle (`tests/fixtures/accord_holder_a1_real_custody.json`) — the
//! same bytes now baked as `src/federation/genesis/canonical_seed.json`. It is
//! public material only: public keys, signatures, and the YubiKey PIV
//! attestation certificates, which are public by construction.
//!
//! What is asserted, on every backend persist ships:
//!
//! - the REAL holder record is admitted end to end through `put_public_key`;
//! - a TAMPERED PIV cert is refused **naming the broken sha256 binding**;
//! - an UNKNOWN custody tier is refused **naming the tier**;
//! - the pre-existing `Hardware` and `SoftwareOnly_TEST` arms are unaffected.

#![cfg(feature = "sqlite")]

use ciris_persist::federation::hardware_attestation::HardwareAttestationPolicy;
use ciris_persist::federation::{FederationDirectory, SignedKeyRecord};

/// The A1 holder record as the ceremony produced it — real hardware custody.
const A1_REAL: &str = include_str!("fixtures/accord_holder_a1_real_custody.json");

fn a1_record() -> SignedKeyRecord {
    serde_json::from_str(A1_REAL).expect("the vendored A1 holder record must parse")
}

/// The custody evidence value off the real record.
fn a1_evidence() -> serde_json::Value {
    a1_record()
        .record
        .attestation_evidence
        .expect("the real A1 record carries custody evidence")
}

// ---------------------------------------------------------------------------
// The policy gate, against the real artifact
// ---------------------------------------------------------------------------

/// #554 — the defect itself: the real ceremony's custody attestation was
/// unrepresentable, so persist refused its own production holders with
/// `malformed: data did not match any variant of untagged enum
/// AttestationEvidence`. It must now be ADMITTED.
#[test]
fn real_yubikey_custody_attestation_is_admitted_554() {
    let p = HardwareAttestationPolicy::default();
    p.check("A1", Some(&a1_evidence()), chrono::Utc::now())
        .expect("#554: the real ceremony's custody attestation must be admissible");
}

/// #554 — the sha256 binding is load-bearing, not decorative. Flip one byte of
/// the slot-9c attestation cert hex and the refusal must NAME the broken
/// binding: the certs ride unsigned in the outer body, bound to the holder's
/// signature only through the sha256 commitments inside the signed envelope.
#[test]
fn tampered_piv_cert_is_refused_naming_the_binding_554() {
    let p = HardwareAttestationPolicy::default();
    let mut ev = a1_evidence();
    let hex = ev["body"]["yubikey_piv_attestation_9c_hex"]
        .as_str()
        .expect("9c hex present")
        .to_string();
    // Flip the final nibble — same length, same parse, different bytes.
    let mut tampered = hex[..hex.len() - 1].to_string();
    tampered.push(if hex.ends_with('0') { '1' } else { '0' });
    ev["body"]["yubikey_piv_attestation_9c_hex"] = serde_json::json!(tampered);

    let err = p
        .check("A1", Some(&ev), chrono::Utc::now())
        .expect_err("#554: a tampered PIV cert must not be admitted");
    let msg = err.to_string();
    assert!(
        msg.contains("yubikey_piv_attestation_9c"),
        "#554: the refusal must name the broken binding, got: {msg}"
    );
    assert!(
        !msg.contains("malformed: data did not match any variant"),
        "#554: a binding failure must not read as a parser bug, got: {msg}"
    );
}

/// #554 — the same binding check over the CHAIN certs, not just the leaf.
#[test]
fn tampered_chain_cert_is_refused_naming_the_binding_554() {
    let p = HardwareAttestationPolicy::default();
    let mut ev = a1_evidence();
    let first = ev["body"]["yubikey_attestation_chain_hex"][0]
        .as_str()
        .expect("chain[0] hex present")
        .to_string();
    let mut tampered = first[..first.len() - 1].to_string();
    tampered.push(if first.ends_with('0') { '1' } else { '0' });
    ev["body"]["yubikey_attestation_chain_hex"][0] = serde_json::json!(tampered);

    let err = p
        .check("A1", Some(&ev), chrono::Utc::now())
        .expect_err("#554: a tampered chain cert must not be admitted");
    assert!(
        err.to_string().contains("yubikey_attestation_chain"),
        "#554: the refusal must name the broken chain binding, got: {err}"
    );
}

/// #554 — `custody_tier` is a holder SELF-CLAIM, so it is allowlisted, never
/// echoed. An unrecognized tier is refused by a message naming the tier.
#[test]
fn unknown_custody_tier_is_refused_naming_the_tier_554() {
    let p = HardwareAttestationPolicy::default();
    let mut ev = a1_evidence();
    ev["body"]["signed_envelope"]["custody_tier"] = serde_json::json!("air_gapped_hsm_supreme");

    let err = p
        .check("A1", Some(&ev), chrono::Utc::now())
        .expect_err("#554: an unrecognized custody tier must not be admitted");
    let msg = err.to_string();
    assert!(
        msg.contains("air_gapped_hsm_supreme"),
        "#554: the refusal must name the tier it got, got: {msg}"
    );
}

/// #554 — the holder cannot present ANOTHER holder's custody attestation: the
/// envelope's `holder_key_id` is bound to the row's `key_id`.
#[test]
fn custody_attestation_for_another_holder_is_refused_554() {
    let p = HardwareAttestationPolicy::default();
    let err = p
        .check("B1", Some(&a1_evidence()), chrono::Utc::now())
        .expect_err("#554: A1's custody attestation must not admit B1");
    assert!(
        err.to_string().contains("holder_key_id"),
        "#554: the refusal must name the identity binding, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// End to end: put_public_key, on every backend
// ---------------------------------------------------------------------------

/// The shared body: the REAL holder record is admitted, and reads back.
async fn admits_real_holder<D: FederationDirectory + ?Sized>(dir: &D) {
    let rec = a1_record();
    dir.put_public_key(rec.clone())
        .await
        .expect("#554: put_public_key must ADMIT the real accord holder A1");
    let back = dir
        .lookup_public_key("A1")
        .await
        .expect("lookup")
        .expect("#554: the admitted holder must read back");
    assert_eq!(back.key_id, "A1");
    assert_eq!(
        back.pubkey_ed25519_base64, rec.record.pubkey_ed25519_base64,
        "#554: the stored row must be the ceremony's record"
    );
    assert!(
        back.attestation_evidence.is_some(),
        "#554: the custody evidence must be preserved — it IS the audit trail"
    );
}

#[tokio::test]
async fn memory_admits_the_real_accord_holder_554() {
    let backend = ciris_persist::store::memory::MemoryBackend::new();
    admits_real_holder(&backend).await;
}

#[tokio::test]
async fn sqlite_admits_the_real_accord_holder_554() {
    use ciris_persist::store::backend::Backend as _;
    let backend = ciris_persist::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    backend.run_migrations().await.unwrap();
    admits_real_holder(&backend).await;
}

// ---------------------------------------------------------------------------
// One verdict for one artifact (#554 deliverable 2)
// ---------------------------------------------------------------------------

/// #554 — **a bundle that verifies is a bundle that installs.**
///
/// Before this cut the two validators disagreed about the same bytes:
/// `verify_bundle_quorum` passed the production bundle (structure, signatures,
/// 2-of-3 quorum all green) while `put_public_key` refused the very holders it
/// carried as `malformed`. A producer running the bundle verifier got a green
/// light and shipped an artifact that could not install — and the refusal
/// surfaced at ingest with no hint that the verifier and the gate disagreed
/// about what a valid holder record is.
///
/// The fix is one predicate, one impl: the bundle verifier runs holder-evidence
/// admissibility through the SAME [`HardwareAttestationPolicy::check`] the put
/// gate uses. This test asserts they now agree — both admit.
#[tokio::test]
async fn bundle_verifier_and_put_gate_agree_on_holder_evidence_554() {
    use ciris_persist::federation::genesis::{
        canonical_genesis_bundle, effective_accord_holder_records, verify_bundle_quorum,
    };

    let backend = ciris_persist::store::memory::MemoryBackend::new();
    backend
        .seed_genesis_accord_holders(&effective_accord_holder_records())
        .await
        .expect("seed the baked A1/B1/C1 roster");

    let bundle = canonical_genesis_bundle();
    let verified = verify_bundle_quorum(&backend, bundle)
        .await
        .expect("#554: the production bundle must verify");
    assert_eq!(
        verified.distinct_holders(),
        2,
        "A1 + B1 hybrid authorizations — 2-of-3"
    );

    // The SAME artifact's holders must pass the SAME gate the put path runs.
    // Pre-#554 this half refused every holder the verifier had just blessed.
    let p = HardwareAttestationPolicy::default();
    for h in &bundle.holders {
        p.check(
            &h.record.key_id,
            h.record.attestation_evidence.as_ref(),
            chrono::Utc::now(),
        )
        .unwrap_or_else(|e| {
            panic!(
                "#554: holder {} verified in the bundle but was refused by the put \
                 gate — the two validators must not disagree: {e}",
                h.record.key_id
            )
        });
    }
}

/// #554 — the wiring, not merely the agreement: a bundle whose holder evidence
/// would be REFUSED at install time must be refused by the VERIFIER.
///
/// This was the sharp case. Pre-#554 such a bundle verified green and then
/// failed at ingest; #554 made the verifier catch it and SAY it was reporting
/// an install-time refusal.
///
/// **v31.2.0 (CIRISPersist#660) changed which gate fires first, and the old
/// premise here is now false.** This comment used to read *"`authorization_digest`
/// covers holder `key_id`s only, not their evidence — so tampering with a
/// holder's custody attestation leaves the 2-of-3 quorum signatures perfectly
/// valid."* The widened digest binds the whole record CONTENT including
/// `attestation_evidence` — the custody evidence #660 named explicitly — so
/// tampering with it now breaks the hybrid signature outright, before the
/// install-time check is ever reached.
///
/// That is strictly stronger, not weaker: the tamper is caught earlier and by
/// cryptography rather than by a policy read. So the assertion accepts EITHER
/// refusal and requires only that the bundle does not verify. Pinning the
/// install-time wording alone would fail here for the best possible reason —
/// a neighbouring gate legitimately refusing first.
#[tokio::test]
async fn bundle_with_uninstallable_holder_evidence_is_refused_by_the_verifier_554() {
    use ciris_persist::federation::genesis::{
        canonical_genesis_bundle, effective_accord_holder_records, verify_bundle_quorum,
    };

    let backend = ciris_persist::store::memory::MemoryBackend::new();
    backend
        .seed_genesis_accord_holders(&effective_accord_holder_records())
        .await
        .expect("seed the baked A1/B1/C1 roster");

    let mut bundle = canonical_genesis_bundle().clone();
    // Break ONE holder's cert binding. The quorum signatures are untouched and
    // still verify — the digest does not cover holder evidence.
    let ev = bundle.holders[0]
        .record
        .attestation_evidence
        .as_mut()
        .expect("holder carries evidence");
    ev["body"]["yubikey_piv_attestation_9c_hex"] = serde_json::json!("00ff00ff");

    let err = verify_bundle_quorum(&backend, &bundle)
        .await
        .expect_err("#554: a bundle carrying uninstallable holder evidence must not verify");
    let msg = err.to_string();
    let install_time = msg.contains("would be REFUSED at install time");
    let digest_bound = msg.contains("hybrid authorization failed to verify");
    assert!(
        install_time || digest_bound,
        "#554/#660: a bundle carrying uninstallable holder evidence must be \
         refused either by the install-time read (#554) or by the widened \
         digest that now binds `attestation_evidence` (#660). Got neither: {msg}"
    );
    // Naming the failing CHECK is a property of the install-time read: it
    // inspects the evidence and can say which field failed. The digest arm
    // cannot and should not — a signature check knows only that the bytes
    // moved, which is exactly why it catches tampering the reader might not
    // think to look for. So require the field name only on the arm that can
    // produce it.
    assert!(
        !install_time || msg.contains("yubikey_piv_attestation_9c"),
        "#554: the install-time refusal must name the failing check, got: {msg}"
    );
}

/// DSN-gated Postgres twin — the memory backend tolerates what a real column
/// type does not (the recurring class: memory-only proof is not proof).
#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_admits_the_real_accord_holder_554() {
    use ciris_persist::store::backend::Backend as _;
    let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL not set");
        return;
    };
    let backend = ciris_persist::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .expect("pg connect");
    backend.run_migrations().await.unwrap();
    // Re-runnable without cleanup: A1 is the genesis holder, so a shared test
    // database may already hold it from the seed path. The record is the same
    // one (the seed and this fixture differ only in RFC-3339 offset spelling,
    // which parses to the same instant), so `put_public_key` is an idempotent
    // no-op rather than a conflict.
    admits_real_holder(&backend).await;
}
