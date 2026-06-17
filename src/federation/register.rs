//! Canonical federation-key registration admission gate
//! (v8.8.0, CIRISPersist#234, CEG 1.0-RC28/RC29 §5.6.8.15).
//!
//! # Why this module exists
//!
//! §5.6.8.15 (`consent:replication`) pins the **normative-honesty**
//! layering for out-of-group federation peering: the substrate gate
//! that lets peer **P**'s corpus admit granting node **G**'s
//! replicated rows is **G's key existing in P's `federation_keys`**
//! (registration), plus the §7 reserved-prefix identity rules. The
//! `consent:replication` attestation is the *governance/audit* record
//! of intent; it does **not** add a substrate admission check. So the
//! single load-bearing security check for every peering is one
//! operation: **register (and later deregister/expire) a peer's
//! federation key**, with hybrid-signature verification + §7
//! reserved-prefix identity rules applied at that gate.
//!
//! Before v8.8.0 two fabric siblings (CIRISServer `src/peer.rs`,
//! CIRISStatus `src/ceg.rs`) reached this gate from opposite sides,
//! each re-deriving "register this peer's key + enforce admission" —
//! a DRY violation on the *single most security-load-bearing* step in
//! the peering flow. [`verify_key_registration`] is the one canonical
//! implementation siblings call (via
//! [`Engine::register_federation_key`](crate::Engine::register_federation_key))
//! rather than re-derive.
//!
//! # What the gate verifies (the §5.6.8.15 reading)
//!
//! The registration is **hybrid-verified against the registering
//! key's own public keys** — proof-of-possession over the canonical
//! `registration_envelope`. This is the model
//! `docs/FEDERATION_DIRECTORY.md` §"Write authority — scrub-signature
//! is auth" pins: *"Persist accepts `federation_keys` writes from any
//! caller whose row carries a valid scrub-signature whose
//! `scrub_key_id` either chains to a steward via the FK chain or is
//! itself out-of-band-anchored. The cryptographic check is the auth
//! check."*
//!
//! The scrub signature on a [`KeyRecord`] is signed by the
//! `scrub_key_id` row:
//!
//! - **Self-attested (proof-of-possession), `scrub_key_id == key_id`**
//!   — the common peering case. The registering key demonstrates
//!   control of its own private keys over the registration envelope;
//!   the verifier reads the pubkeys directly off the submitted record.
//! - **Granting authority, `scrub_key_id != key_id`** — the signer
//!   must already exist in `federation_keys` (it chains to an anchor);
//!   the verifier resolves the signer's pubkeys from the directory.
//!   An unknown signer ⇒ rejected (fail-secure).
//!
//! Either way the cryptographic check is bound to **`scrub_key_id`'s**
//! keys — never to an unverified field of the submitted row alone.
//!
//! The canonical bytes the signature covers are
//! [`ceg_produce_canonicalize`](crate::verify::canonical::ceg_produce_canonicalize)`(registration_envelope)`
//! — the same JCS/Python-compat produce gate the rest of the fabric
//! signs through (post-#871 the whole fabric is on JCS). To prove the
//! verifier and the producer agree on the canonicalizer, the gate also
//! cross-checks `SHA-256(canonical) == original_content_hash`: a
//! producer that signed a *different* canonical form fails the hash
//! check first, with a clear error, and is **not stored**
//! (fail-secure).
//!
//! Verification runs in [`HybridPolicy::Strict`](crate::verify::HybridPolicy::Strict)
//! — both Ed25519 and ML-DSA-65 are REQUIRED. Peering is a high-stakes
//! domain; a hybrid-pending (Ed25519-only) registration is rejected.
//!
//! # §7 reserved-prefix identity rules at registration
//!
//! The reserved-*identity-type* rule that binds at registration is the
//! `accord_holder` hardware-attestation gate (§7.2 / §9.1): an
//! `accord_holder` row MUST carry valid hardware-attestation evidence.
//! That gate already lives in
//! [`FederationDirectory::put_public_key`](crate::federation::FederationDirectory::put_public_key)
//! (the `hardware_attestation_policy().check(...)` call) and the V048
//! schema CHECK; this module composes `put_public_key` and so does not
//! weaken or duplicate it. The §7 *emitter* rules (`accord:*`,
//! `system:*`, …) are dimension-scoped and bind at attestation
//! admission ([`super::admission`]), not at key registration.
//!
//! # Fail-secure
//!
//! ANY verification or rule failure ⇒ a typed [`Error`] (stable
//! `kind()` token [`Error::SignatureInvalid`] ⇒
//! `"federation_signature_invalid"`, or [`Error::InvalidArgument`])
//! and the row is **NOT stored** — no `put_public_key` call is made.
//! Unknown/unverified ⇒ not registered ⇒ that peer's replicated rows
//! are not admitted. That is the whole point of §5.6.8.15.

use sha2::{Digest, Sha256};

use super::types::{algorithm, KeyRecord};
use super::{Error, FederationDirectory};
use crate::verify::canonical::ceg_produce_canonicalize;
use crate::verify::{verify_hybrid, HybridPolicy, VerifyOutcome};

/// Verify a [`KeyRecord`] registration against the §5.6.8.15 admission
/// gate, BEFORE any store. Generic over [`FederationDirectory`] so it
/// composes against any backend (postgres, sqlite, memory) — the
/// directory is only consulted to resolve a granting-authority
/// signer's pubkeys when `scrub_key_id != key_id`.
///
/// On success returns the [`VerifyOutcome`] (always
/// [`VerifyOutcome::HybridVerified`] under the Strict policy this gate
/// uses); the caller then stores the row via `put_public_key`. On ANY
/// failure returns a typed [`Error`] and the caller MUST NOT store the
/// row.
///
/// This does **not** apply the `accord_holder` hardware-attestation
/// gate or the `algorithm == hybrid` check itself — those live in
/// `put_public_key` and the schema, and the caller
/// ([`Engine::register_federation_key`](crate::Engine::register_federation_key))
/// composes them by calling `put_public_key` only after this returns
/// `Ok`. The `algorithm` check is *additionally* asserted here as a
/// cheap fail-fast so a non-hybrid row never reaches the (expensive)
/// PQC verify.
pub async fn verify_key_registration<F>(
    directory: &F,
    record: &KeyRecord,
) -> Result<VerifyOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    // Fail-fast: algorithm must be hybrid. put_public_key + the schema
    // CHECK enforce this too; asserting here keeps a non-hybrid row
    // from ever reaching the PQC verify, and gives the same
    // InvalidArgument shape the store path returns.
    if record.algorithm != algorithm::HYBRID {
        return Err(Error::InvalidArgument(format!(
            "algorithm must be 'hybrid' for registration (got '{}')",
            record.algorithm
        )));
    }

    if record.key_id.is_empty() {
        return Err(Error::InvalidArgument(
            "key_id must be non-empty for registration".to_string(),
        ));
    }
    if record.scrub_key_id.is_empty() {
        return Err(Error::InvalidArgument(
            "scrub_key_id must be non-empty for registration".to_string(),
        ));
    }

    // Canonicalize the registration envelope through the CEG produce
    // gate — the same canonical form the producer signed. Cross-check
    // its SHA-256 against the row's declared original_content_hash so
    // a canonicalizer disagreement (producer signed a different shape)
    // is caught here, fail-secure, rather than masked as a downstream
    // signature mismatch.
    let canonical = ceg_produce_canonicalize(&record.registration_envelope)
        .map_err(|e| Error::InvalidArgument(format!("registration_envelope canonicalize: {e}")))?;
    let computed_hash = hex::encode(Sha256::digest(&canonical));
    if computed_hash != record.original_content_hash {
        return Err(Error::SignatureInvalid(format!(
            "registration original_content_hash mismatch: envelope canonicalizes to {computed_hash}, \
             record declares {}",
            record.original_content_hash
        )));
    }

    // Resolve the signer's (scrub_key_id's) public keys. Self-attested
    // proof-of-possession (scrub_key_id == key_id) reads the pubkeys
    // straight off the submitted record; a granting-authority
    // signature (scrub_key_id != key_id) resolves them from the
    // directory — an unknown signer is rejected (fail-secure).
    let (ed25519_pubkey_b64, ml_dsa_65_pubkey_b64) = if record.scrub_key_id == record.key_id {
        (
            record.pubkey_ed25519_base64.clone(),
            record.pubkey_ml_dsa_65_base64.clone(),
        )
    } else {
        let signer = directory
            .lookup_public_key(&record.scrub_key_id)
            .await?
            .ok_or_else(|| {
                Error::SignatureInvalid(format!(
                    "registration signer (scrub_key_id={}) is not registered",
                    record.scrub_key_id
                ))
            })?;
        (signer.pubkey_ed25519_base64, signer.pubkey_ml_dsa_65_base64)
    };

    // Strict hybrid verify: both Ed25519 and ML-DSA-65 REQUIRED.
    // Peering is high-stakes; a hybrid-pending (Ed25519-only)
    // registration is rejected. row_age is irrelevant under Strict.
    let outcome = verify_hybrid(
        &canonical,
        &record.scrub_signature_classical,
        record.scrub_signature_pqc.as_deref(),
        &ed25519_pubkey_b64,
        ml_dsa_65_pubkey_b64.as_deref(),
        HybridPolicy::Strict,
        None,
    )
    .map_err(|e| {
        Error::SignatureInvalid(format!("registration hybrid-verify: {e} ({})", e.kind()))
    })?;

    Ok(outcome)
}

#[cfg(all(test, any(feature = "postgres", feature = "sqlite")))]
mod tests {
    //! v8.8.0 (CIRISPersist#234) — the §5.6.8.15 admission-gate matrix,
    //! run identically against sqlite and (when `CIRIS_PERSIST_TEST_PG_URL`
    //! is set) postgres via [`run_register_matrix`]. Test (b) — bad/missing
    //! signature ⇒ REJECTED + NOT stored — is the load-bearing fail-secure
    //! guard.

    use super::*;
    use crate::engine::Engine;
    use crate::federation::types::{algorithm, identity_type};
    use crate::federation::{KeyRecord, SignedKeyRecord};
    use crate::signing::LocalSigner;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_keyring::PqcSigner as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::sync::Arc;

    /// Engine scrub-signer for tests — deterministic seed; the engine's
    /// own signing identity is independent of the peer keys being
    /// registered.
    fn test_signer() -> Arc<LocalSigner> {
        let signing_key = SigningKey::from_bytes(&[0x7Au8; 32]);
        Arc::new(LocalSigner::from_parts(
            signing_key,
            "register-test-steward".to_string(),
            None,
            None,
        ))
    }

    /// Build a fully hybrid-signed (Ed25519 + ML-DSA-65) self-attested
    /// `KeyRecord` — `scrub_key_id == key_id`, proof-of-possession over
    /// the registration envelope. Returns the record; the seeds make
    /// it deterministic. `tamper` mutates the envelope AFTER signing
    /// (for the tampered-envelope test); `drop_pqc` strips the PQC
    /// signature (for the hybrid-pending rejection test); `corrupt_ed`
    /// flips the classical signature.
    async fn signed_self_record(
        key_id: &str,
        identity_type: &str,
        attestation_evidence: Option<serde_json::Value>,
        tamper: bool,
        drop_pqc: bool,
        corrupt_ed: bool,
    ) -> KeyRecord {
        // Deterministic-per-key seeds (first 8 bytes from the key_id).
        let mut seed = [0x11u8; 32];
        for (i, b) in key_id.bytes().take(32).enumerate() {
            seed[i] = b;
        }
        let ed_sk = SigningKey::from_bytes(&seed);
        let ed_pk = ed_sk.verifying_key().to_bytes();

        let mldsa = ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&seed, "reg-test-mldsa")
            .expect("seed length checked");
        let mldsa_pk = mldsa.public_key().await.expect("ml-dsa pk");

        let envelope = serde_json::json!({
            "key_id": key_id,
            "purpose": "federation-peering",
        });
        let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize");
        let original_content_hash = hex::encode(Sha256::digest(&canonical));

        // Ed25519 over canonical.
        let ed_sig = ed_sk.sign(&canonical).to_bytes();
        // ML-DSA-65 over the BOUND input (canonical || classical_sig).
        let mut bound = Vec::with_capacity(canonical.len() + ed_sig.len());
        bound.extend_from_slice(&canonical);
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).await.expect("ml-dsa sign");

        let mut classical_b64 = B64.encode(ed_sig);
        if corrupt_ed {
            // Flip to a valid-length-but-wrong signature: sign a
            // DIFFERENT message so length is right but verify fails.
            let other = ed_sk.sign(b"not-the-registration-envelope").to_bytes();
            classical_b64 = B64.encode(other);
        }

        let now = chrono::Utc::now();
        let mut record = KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: B64.encode(ed_pk),
            pubkey_ml_dsa_65_base64: Some(B64.encode(&mldsa_pk)),
            algorithm: algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash,
            scrub_signature_classical: classical_b64,
            scrub_signature_pqc: if drop_pqc {
                None
            } else {
                Some(B64.encode(&pqc_sig))
            },
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: if drop_pqc { None } else { Some(now) },
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence,
        };
        if drop_pqc {
            // A hybrid-pending row also drops the PQC pubkey.
            record.pubkey_ml_dsa_65_base64 = None;
        }
        if tamper {
            // Mutate the envelope AFTER signing — the signature now
            // covers a different envelope than the one stored. The
            // original_content_hash still matches the NEW envelope so
            // the hash-cross-check passes and the failure surfaces as
            // a signature mismatch (the stronger guard).
            record.registration_envelope = serde_json::json!({
                "key_id": key_id,
                "purpose": "TAMPERED",
            });
            let new_canonical =
                ceg_produce_canonicalize(&record.registration_envelope).expect("canonicalize");
            record.original_content_hash = hex::encode(Sha256::digest(&new_canonical));
        }
        record
    }

    /// The full §5.6.8.15 admission-gate matrix, backend-agnostic.
    async fn run_register_matrix(engine: &Engine, run_tag: &str) {
        let directory = engine.federation_directory();

        // (a) valid hybrid-signed registration → ADMITTED + stored.
        let valid_id = format!("peer-valid-{run_tag}");
        let rec =
            signed_self_record(&valid_id, identity_type::AGENT, None, false, false, false).await;
        engine
            .register_federation_key(SignedKeyRecord { record: rec })
            .await
            .expect("(a) valid registration must be admitted");
        let read = directory
            .lookup_public_key(&valid_id)
            .await
            .expect("lookup");
        assert!(
            read.is_some(),
            "(a) admitted key must be readable via lookup_public_key"
        );

        // (b) bad/missing ML-DSA-65 (hybrid-pending under Strict) →
        // REJECTED, NOT stored. THE load-bearing fail-secure guard.
        let pending_id = format!("peer-pending-{run_tag}");
        let pending = signed_self_record(
            &pending_id,
            identity_type::AGENT,
            None,
            false,
            true, // drop_pqc
            false,
        )
        .await;
        let err = engine
            .register_federation_key(SignedKeyRecord { record: pending })
            .await
            .expect_err("(b) hybrid-pending registration must be rejected under Strict");
        assert_eq!(
            err.kind(),
            "federation_signature_invalid",
            "(b) rejection must be a signature/verification failure"
        );
        assert!(
            directory
                .lookup_public_key(&pending_id)
                .await
                .expect("lookup")
                .is_none(),
            "(b) rejected key must NOT be queryable (fail-secure: not stored)"
        );

        // (b') bad Ed25519 signature → REJECTED, NOT stored.
        let bad_ed_id = format!("peer-bad-ed-{run_tag}");
        let bad_ed = signed_self_record(
            &bad_ed_id,
            identity_type::AGENT,
            None,
            false,
            false,
            true, // corrupt_ed
        )
        .await;
        let err = engine
            .register_federation_key(SignedKeyRecord { record: bad_ed })
            .await
            .expect_err("(b') bad Ed25519 signature must be rejected");
        assert_eq!(err.kind(), "federation_signature_invalid");
        assert!(
            directory
                .lookup_public_key(&bad_ed_id)
                .await
                .expect("lookup")
                .is_none(),
            "(b') rejected key must NOT be queryable"
        );

        // (c) tampered registration_envelope (sig doesn't match) →
        // REJECTED.
        let tampered_id = format!("peer-tampered-{run_tag}");
        let tampered = signed_self_record(
            &tampered_id,
            identity_type::AGENT,
            None,
            true, // tamper
            false,
            false,
        )
        .await;
        let err = engine
            .register_federation_key(SignedKeyRecord { record: tampered })
            .await
            .expect_err("(c) tampered envelope must be rejected");
        assert_eq!(err.kind(), "federation_signature_invalid");
        assert!(
            directory
                .lookup_public_key(&tampered_id)
                .await
                .expect("lookup")
                .is_none(),
            "(c) tampered key must NOT be queryable"
        );

        // (d) §7 reserved-identity violation: accord_holder with NO
        // hardware attestation → REJECTED (existing accord-holder gate
        // in put_public_key is preserved — the registration is
        // hybrid-valid but the accord_holder gate refuses it).
        let accord_id = format!("peer-accord-{run_tag}");
        let accord = signed_self_record(
            &accord_id,
            identity_type::ACCORD_HOLDER,
            None, // no attestation_evidence
            false,
            false,
            false,
        )
        .await;
        engine
            .register_federation_key(SignedKeyRecord { record: accord })
            .await
            .expect_err("(d) accord_holder without hardware attestation must be rejected");
        assert!(
            directory
                .lookup_public_key(&accord_id)
                .await
                .expect("lookup")
                .is_none(),
            "(d) rejected accord_holder must NOT be queryable"
        );

        // (f) non-hybrid algorithm → REJECTED (existing check preserved;
        // caught by the registration gate's fail-fast).
        let nonhybrid_id = format!("peer-nonhybrid-{run_tag}");
        let mut nonhybrid = signed_self_record(
            &nonhybrid_id,
            identity_type::AGENT,
            None,
            false,
            false,
            false,
        )
        .await;
        nonhybrid.algorithm = "ed25519-only".to_owned();
        let err = engine
            .register_federation_key(SignedKeyRecord { record: nonhybrid })
            .await
            .expect_err("(f) non-hybrid algorithm must be rejected");
        assert_eq!(err.kind(), "federation_invalid_argument");
        assert!(
            directory
                .lookup_public_key(&nonhybrid_id)
                .await
                .expect("lookup")
                .is_none(),
            "(f) non-hybrid key must NOT be queryable"
        );

        // (e) deregister/expire → the key is no longer admit-valid. We
        // register a fresh peer then deregister it via a revocation;
        // a revocation row is then queryable for the key (the consumer
        // applies its policy on read and ceases admitting).
        let dereg_id = format!("peer-dereg-{run_tag}");
        let dereg =
            signed_self_record(&dereg_id, identity_type::AGENT, None, false, false, false).await;
        engine
            .register_federation_key(SignedKeyRecord {
                record: dereg.clone(),
            })
            .await
            .expect("(e) register the peer to be deregistered");
        // Build a self-signed revocation (revoking_key_id empty skips
        // the trust gate; scrub_key_id = the revoked key, self-revoke).
        let now = chrono::Utc::now();
        let rev_envelope = serde_json::json!({"revokes": dereg_id});
        let rev_canonical = ceg_produce_canonicalize(&rev_envelope).expect("canonicalize");
        let revocation = crate::federation::Revocation {
            revocation_id: uuid::Uuid::new_v4().to_string(),
            revoked_key_id: dereg_id.clone(),
            revoking_key_id: dereg_id.clone(),
            reason: Some("consent:replication withdrawn".to_owned()),
            revoked_at: now,
            effective_at: now,
            revocation_envelope: rev_envelope,
            original_content_hash: hex::encode(Sha256::digest(&rev_canonical)),
            scrub_signature_classical: "AA".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: dereg_id.clone(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            observed_region: crate::federation::verify_coord::region::US.to_owned(),
            persist_row_hash: String::new(),
        };
        engine
            .deregister_federation_key(crate::federation::SignedRevocation { revocation })
            .await
            .expect("(e) deregister must store the revocation");
        let revs = directory
            .revocations_for(&dereg_id)
            .await
            .expect("revocations_for");
        assert_eq!(
            revs.len(),
            1,
            "(e) deregistered key must carry a revocation the consumer honors on read"
        );
        assert_eq!(revs[0].revoked_key_id, dereg_id);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn register_matrix_sqlite() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct sqlite engine");
        run_register_matrix(&engine, "sqlite").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn register_matrix_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping register_matrix_postgres: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let engine = Engine::with_signer(test_signer(), &dsn)
            .await
            .expect("construct postgres engine");
        // Run-scoped unique tag so parallel/repeat runs don't collide on
        // the federation_keys PK (key_id is TEXT; uuid-suffix it).
        let tag = format!("pg-{}", uuid::Uuid::new_v4().simple());
        run_register_matrix(&engine, &tag).await;
    }
}
