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
use ciris_persist::federation::SignedKeyRecord;

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
    p.check("A1", None, Some(&a1_evidence()), chrono::Utc::now())
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
        .check("A1", None, Some(&ev), chrono::Utc::now())
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
        .check("A1", None, Some(&ev), chrono::Utc::now())
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
        .check("A1", None, Some(&ev), chrono::Utc::now())
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
        .check("B1", None, Some(&a1_evidence()), chrono::Utc::now())
        .expect_err("#554: A1's custody attestation must not admit B1");
    assert!(
        err.to_string().contains("holder_key_id"),
        "#554: the refusal must name the identity binding, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// v62.0.0 (JSON-cut slice E4) — the end-to-end legs are deleted
// ---------------------------------------------------------------------------
//
// `sqlite_admits_the_real_accord_holder_554` / `postgres_admits_the_real_
// accord_holder_554` put the A1 holder's EARLIER-FORM `SignedKeyRecord`
// through `put_public_key`, and `bundle_verifier_and_put_gate_agree_on_
// holder_evidence_554` / `bundle_with_uninstallable_holder_evidence_is_
// refused_by_the_verifier_554` read the bundle/1 genesis
// (`canonical_genesis_bundle`, `verify_bundle_quorum`). Both are earlier-form
// objects the v62 node refuses; they asserted earlier-form behaviour and were
// deleted, not rewritten. The custody gate's verdict on the REAL captured
// artifact is still witnessed above (the five `HardwareAttestationPolicy`
// tests); the edition-2 `key:record` custody path is witnessed by the
// bundle/2 test ceremony (`edition2::fixture_genesis`, Verify's mock YubiKey
// PIV root), since a real holder's PIV binding cannot sign a test statement.
