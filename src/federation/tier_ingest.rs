//! Federation-tier ingest admission gate — PQC-mandatory hybrid-signature
//! verification at the bulk per-trace store/replicate path
//! (v9.0.0, CIRISPersist#237, CC 5.3.2.4.3.1).
//!
//! # Why this module exists
//!
//! CC 5.3.2.4.3 pins the substrate invariant
//! `tier = federation ⟹ hybrid signature present`, and CC 5.3.2.4.3.1
//! makes "present" mean **verified at the admission gate** — and binds
//! it to the **durable store + replication path, not only the
//! operational-authority gates**: *"every federation-tier attestation,
//! including the bulk per-trace / store-and-replicate path … MUST carry
//! (and a verifier MUST check on ingest) the ML-DSA-65 half exactly as a
//! key_grant does; there is no 'operational authority vs testimony leaf'
//! exemption."* Store-then-quarantine is explicitly non-conformant:
//! a substrate persisting/replicating a federation-tier row whose
//! envelope signature lacks a valid ML-DSA-65 half MUST reject it **at
//! the ingest gate**.
//!
//! Before v9.0.0, [`FederationDirectory::put_attestation`](crate::federation::FederationDirectory::put_attestation)
//! ran only [`AdmissionGate::check_federation`](crate::federation::AdmissionGate::check_federation)
//! — a trust-**threshold** check on the *key* — then INSERTed. The row's
//! envelope hybrid signature (`scrub_signature_classical` /
//! `scrub_signature_pqc`) was merely **stored**, never verified at the
//! federation-tier write/replicate path. The `tier = federation` label
//! was trusted. Hybrid-verify-at-gate existed only on
//! [`register_federation_key`](crate::Engine::register_federation_key)
//! ([`super::register`], v8.8.0) and the fountain store-path (v8.4.0) —
//! NOT on the federation-tier testimony corpus, the single most
//! forge-exposed surface in the federation (the "store at massive scale"
//! CEWP crux: content-addressing is no defense against a CRQC-era
//! adversary who breaks Ed25519, mints a backdated trace under a
//! historical key, and hashes *their own* forgery).
//!
//! [`verify_federation_tier_ingest`] closes that gap. It is the
//! federation-tier sibling of [`super::register::verify_key_registration`]
//! and shares its exact verify semantics.
//!
//! # The signing contract (byte-for-byte with `register.rs`)
//!
//! The canonical bytes the producer signed are
//! [`ceg_produce_canonicalize`](crate::verify::canonical::ceg_produce_canonicalize)`(attestation_envelope)`
//! — the same JCS/Python-compat produce gate the rest of the fabric
//! signs through (post-#871 the whole fabric is on JCS). The gate
//! cross-checks `SHA-256(canonical) == original_content_hash` first: a
//! producer that signed a *different* canonical form fails the hash
//! check with a clear error, and is **not stored** (fail-secure) —
//! exactly as [`super::register::verify_key_registration`] does.
//!
//! Verification runs in [`HybridPolicy::Strict`](crate::verify::HybridPolicy::Strict):
//! **both** Ed25519 over `JCS(envelope)` AND ML-DSA-65 over the bound
//! `JCS(envelope) ‖ ed25519_sig` ([CC 3.1.2.1] bound-payload form,
//! applied inside the hybrid verifier) are REQUIRED. There is no
//! `require_hybrid: false` posture (CC 5.3.2.4.3.1) — a classical-only /
//! hybrid-pending federation-tier row is rejected.
//!
//! The signature is verified against the attester's **REGISTERED**
//! pubkeys, resolved via
//! [`lookup_public_key`](crate::federation::FederationDirectory::lookup_public_key)
//! on `attesting_key_id` — **never** against pubkeys carried on the row
//! alone. An unknown/unregistered attester ⇒ rejected (fail-secure):
//! there are no pubkeys to verify against, so the row cannot be admitted.
//!
//! # The breaking boundary — local-tier is EXEMPT
//!
//! The mandate is at the **federation admission boundary only**. A
//! `tier = local` row (producer-only authority, signature deferred per
//! CC 5.3.2.2, visible only to the producing occurrence) is a no-op for
//! this gate — non-PQC producers are confined to local-tier until they
//! complete PQC wiring. This is the v9.0.0 BREAKING change: a
//! classical-only federation-tier write that was admitted pre-v9.0.0 is
//! now non-conformant and rejected here.
//!
//! # Fail-secure
//!
//! ANY missing/invalid signature, unknown attester, or canonicalizer
//! mismatch ⇒ a typed [`Error::FederationTierUnverified`] (stable
//! `kind()` token `"federation_federation_tier_unverified"`) and the row
//! is **NOT stored**. Verify-before-mutation (AV-9). The gate composes
//! with — does not replace — the existing
//! [`AdmissionGate::check_federation`](crate::federation::AdmissionGate)
//! trust-threshold check and the node-agency gate.
//!
//! [CC 3.1.2.1]: the bound-payload form `JCS(envelope) ‖ ed25519_sig`.

use sha2::{Digest, Sha256};

use super::types::attestation_tier;
use super::{Attestation, Error, FederationDirectory};
use crate::verify::canonical::ceg_produce_canonicalize;
use crate::verify::{verify_hybrid, HybridPolicy};

/// Verify a federation-tier [`Attestation`]'s envelope hybrid signature
/// against the §CC 5.3.2.4.3.1 ingest gate, BEFORE any store. Generic
/// over [`FederationDirectory`] so it composes against any backend
/// (postgres, sqlite, memory) — the directory is consulted to resolve
/// the attester's REGISTERED pubkeys.
///
/// **Local-tier rows are EXEMPT** (`Ok(())` no-op): the federation
/// admission boundary is the only place authority crosses, and a
/// local-tier row MAY defer its signature (CC 5.3.2.2).
///
/// For a federation-tier row this runs the **same** verify contract as
/// [`super::register::verify_key_registration`]:
/// 1. canonicalize `attestation_envelope` through
///    [`ceg_produce_canonicalize`] and cross-check
///    `SHA-256(canonical) == original_content_hash` (canonicalizer
///    agreement, fail-secure);
/// 2. resolve the attester's registered Ed25519 + ML-DSA-65 pubkeys via
///    [`FederationDirectory::lookup_public_key`] on `attesting_key_id`
///    (unknown attester ⇒ reject);
/// 3. [`verify_hybrid`] under [`HybridPolicy::Strict`] — both halves
///    REQUIRED.
///
/// On success returns `Ok(())`; the caller then stores the row. On ANY
/// failure returns [`Error::FederationTierUnverified`] and the caller
/// MUST NOT store the row.
pub async fn verify_federation_tier_ingest<F>(directory: &F, row: &Attestation) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    // Local-tier rows are EXEMPT (CC 5.3.2.2 deferred signature) — the
    // mandate is at the federation admission boundary only.
    if row.tier != attestation_tier::FEDERATION {
        return Ok(());
    }

    let reject = |reason: String| Error::FederationTierUnverified {
        attestation_id: row.attestation_id.clone(),
        attesting_key_id: row.attesting_key_id.clone(),
        reason,
    };

    // (1) Canonicalize the attestation envelope through the CEG produce
    // gate — the same canonical form the producer signed — and
    // cross-check its SHA-256 against the row's declared
    // original_content_hash. A canonicalizer disagreement (producer
    // signed a different shape) is caught here, fail-secure, rather than
    // masked as a downstream signature mismatch. Mirrors
    // register.rs::verify_key_registration.
    let canonical = ceg_produce_canonicalize(&row.attestation_envelope)
        .map_err(|e| reject(format!("attestation_envelope canonicalize: {e}")))?;
    let computed_hash = hex::encode(Sha256::digest(&canonical));
    if computed_hash != row.original_content_hash {
        return Err(reject(format!(
            "original_content_hash mismatch: envelope canonicalizes to {computed_hash}, \
             row declares {}",
            row.original_content_hash
        )));
    }

    // (2) Resolve the attester's REGISTERED pubkeys. Verify against the
    // registered key, never pubkeys carried on the row alone — an
    // unknown/unregistered attester has no pubkeys to verify against and
    // is rejected (fail-secure). The FK gate in put_attestation also
    // requires attesting_key_id to exist, but resolving here keeps the
    // gate self-contained and orders the reject as a typed
    // federation-tier-unverified failure.
    let attester = directory
        .lookup_public_key(&row.attesting_key_id)
        .await
        .map_err(|e| reject(format!("attester lookup_public_key: {e} ({})", e.kind())))?
        .ok_or_else(|| {
            reject(format!(
                "attesting_key_id {} is not registered — no pubkeys to verify the \
                 federation-tier signature against",
                row.attesting_key_id
            ))
        })?;

    // (3) Strict hybrid verify: both Ed25519 (over canonical) and
    // ML-DSA-65 (over the bound canonical || classical_sig, applied
    // inside the hybrid verifier) REQUIRED. A classical-only /
    // hybrid-pending federation-tier row (PQC sig absent) is rejected —
    // the load-bearing CC 5.3.2.4.3.1 guard. row_age is irrelevant under
    // Strict.
    verify_hybrid(
        &canonical,
        &row.scrub_signature_classical,
        row.scrub_signature_pqc.as_deref(),
        &attester.pubkey_ed25519_base64,
        attester.pubkey_ml_dsa_65_base64.as_deref(),
        HybridPolicy::Strict,
        None,
    )
    .map_err(|e| reject(format!("hybrid-verify: {e} ({})", e.kind())))?;

    Ok(())
}

/// v9.0.0 (CIRISPersist#237) — shared test-support for the
/// federation-tier ingest gate. Mirrors
/// [`super::operational::test_support`]: a deterministic-per-`key_id`
/// hybrid keypair (so a registered key and a signed attestation derived
/// from the same `key_id` match without threading an identity object
/// through every call site), plus helpers to fill a [`KeyRecord`]'s
/// pubkeys and to sign an attestation envelope. Used by the
/// `put_attestation` test fixtures on all three backends to carry REAL
/// hybrid signatures now that the federation-tier ingest gate is
/// mandatory (CC 5.3.2.4.3.1).
#[cfg(test)]
#[allow(dead_code)]
pub(crate) mod test_support {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer, PqcSigner as _};

    /// Deterministic 32-byte seed for `key_id` — the first ≤32 bytes of
    /// the key_id over a `0x11` fill. Same shape as
    /// `register.rs::tests::signed_self_record`, so the two test corpora
    /// stay coherent.
    fn seed_for(key_id: &str) -> [u8; 32] {
        let mut seed = [0x11u8; 32];
        for (i, b) in key_id.bytes().take(32).enumerate() {
            seed[i] = b;
        }
        seed
    }

    /// The Ed25519 signer for `key_id` (deterministic).
    fn ed_signer(key_id: &str) -> Ed25519Signer {
        Ed25519Signer::from_seed(&seed_for(key_id)).expect("ed seed")
    }

    /// The ML-DSA-65 signer for `key_id` (deterministic), **boxed** —
    /// `MlDsa65Signer` holds the multi-KiB secret key inline, so keeping
    /// it on the heap keeps test stack frames small (several of these in a
    /// single async test frame otherwise overflow the worker stack).
    fn mldsa_signer(key_id: &str) -> Box<MlDsa65Signer> {
        Box::new(MlDsa65Signer::from_seed(&seed_for(key_id)).expect("mldsa seed"))
    }

    /// `key_id`'s registered hybrid pubkeys, base64. Use these to fill a
    /// `KeyRecord`'s `pubkey_ed25519_base64` / `pubkey_ml_dsa_65_base64`
    /// so the registered key matches what [`sign_envelope`] signs with.
    pub fn hybrid_pubkeys(key_id: &str) -> (String, Option<String>) {
        let ed_pk = B64.encode(ed_signer(key_id).public_key().expect("ed pk"));
        let mldsa_pk = B64.encode(mldsa_signer(key_id).public_key().expect("mldsa pk"));
        (ed_pk, Some(mldsa_pk))
    }

    /// Build a PQC-configured [`crate::signing::LocalSigner`] whose
    /// Ed25519 + ML-DSA-65 keypair is the SAME deterministic pair as
    /// [`hybrid_pubkeys`] / [`sign_envelope`] for `key_id`. Use this to
    /// drive product code that hybrid-signs federation-tier withdraws
    /// (evict_actor / takedown handler) in tests, with `key_id`'s key
    /// registered via [`hybrid_pubkeys`] so the ingest gate verifies the
    /// emitted withdraws. `key_id` is the LocalSigner's `key_id` (the
    /// `attesting_key_id` on the emitted rows).
    ///
    /// `ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes` and
    /// `ciris_crypto::MlDsa65Signer::from_seed` derive the SAME ML-DSA-65
    /// keypair from the same seed (both feed the seed to the ml-dsa
    /// keygen), so the LocalSigner's PQC pubkey matches the registered
    /// `pubkey_ml_dsa_65_base64`; a debug_assert pins that invariant.
    pub fn local_signer(key_id: &str) -> std::sync::Arc<crate::signing::LocalSigner> {
        let seed = seed_for(key_id);
        let ed = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pqc = std::sync::Arc::new(
            ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&seed, key_id)
                .expect("mldsa seed length"),
        );
        // The keyring software signer's ML-DSA-65 keypair must match the
        // ciris_crypto signer's pubkey for the same seed (so the key
        // registered via `hybrid_pubkeys` verifies the emitted sig); if it
        // ever diverged, the ingest gate would reject the emitted withdraws
        // and the eviction/takedown tests would fail loudly.
        std::sync::Arc::new(crate::signing::LocalSigner::from_parts(
            ed,
            key_id.to_owned(),
            Some(pqc),
            Some(key_id.to_owned()),
        ))
    }

    /// Hybrid-sign `envelope` (through the CEG produce canonicalizer)
    /// with `signing_key_id`'s deterministic keys. Returns
    /// `(original_content_hash, scrub_signature_classical,
    /// scrub_signature_pqc)` — exactly the three fields the
    /// federation-tier ingest gate verifies. The PQC half signs the
    /// bound payload `canonical || ed25519_sig` (CC 3.1.2.1).
    pub fn sign_envelope(
        signing_key_id: &str,
        envelope: &serde_json::Value,
    ) -> (String, String, Option<String>) {
        let ed = ed_signer(signing_key_id);
        let mldsa = mldsa_signer(signing_key_id);
        let canonical = ceg_produce_canonicalize(envelope).expect("canonicalize");
        let original_content_hash = hex::encode(Sha256::digest(&canonical));
        let ed_sig = ed.sign(&canonical).expect("ed sign");
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).expect("mldsa sign");
        (
            original_content_hash,
            B64.encode(&ed_sig),
            Some(B64.encode(&pqc_sig)),
        )
    }
}

#[cfg(all(test, any(feature = "postgres", feature = "sqlite")))]
mod tests {
    //! v9.0.0 (CIRISPersist#237) — the CC 5.3.2.4.3.1 federation-tier
    //! ingest-gate matrix, run identically against sqlite and (when
    //! `CIRIS_PERSIST_TEST_PG_URL` is set) postgres via [`run_tier_ingest_matrix`].
    //! Test (b) — federation-tier with the ML-DSA-65 half MISSING ⇒
    //! REJECTED + NOT stored — is the load-bearing CC 5.3.2.4.3.1 guard;
    //! test (e) — LOCAL-tier without PQC ⇒ ADMITTED — proves the
    //! breaking-boundary exemption (local-tier producers are not
    //! over-rejected).

    use super::test_support::{hybrid_pubkeys, sign_envelope};
    use crate::engine::Engine;
    use crate::federation::types::{
        algorithm, attestation_tier, attestation_type, cohort_scope, identity_type,
    };
    use crate::federation::{
        Attestation, FederationDirectory, KeyRecord, SignedAttestation, SignedKeyRecord,
    };
    use crate::signing::LocalSigner;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;

    fn test_signer() -> Arc<LocalSigner> {
        let signing_key = SigningKey::from_bytes(&[0x5Au8; 32]);
        Arc::new(LocalSigner::from_parts(
            signing_key,
            "tier-ingest-test-steward".to_string(),
            None,
            None,
        ))
    }

    /// Register `key_id` with REAL deterministic hybrid pubkeys (the
    /// conformant state) via the directory's `put_public_key`. The
    /// registration row's own scrub-signature fields are placeholders —
    /// `put_public_key` does not hybrid-verify the registration (that gate
    /// is `register_federation_key`); only the PUBKEYS must be real for
    /// the federation-tier ingest gate to verify attestations.
    async fn register_hybrid_key(dir: &dyn FederationDirectory, key_id: &str) {
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        let now = chrono::Utc::now();
        let rec = KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: algorithm::HYBRID.to_owned(),
            identity_type: identity_type::AGENT.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
            original_content_hash: "deadbeef".to_owned(),
            scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
        };
        dir.put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("register hybrid key");
    }

    /// Build a `scores` Attestation by `attester` over a fresh envelope.
    /// `sign` controls whether the envelope is hybrid-signed (true) or
    /// carries placeholder/partial signatures. `tier` lets (e) write a
    /// local-tier row.
    fn att(attester: &str, attested: &str, id: &str, tier: &str) -> Attestation {
        let envelope = serde_json::json!({
            "id": id,
            "dimension": "identity_binding:v1",
            "score": 1.0,
            "confidence": 0.9,
        });
        let (och, classical, pqc) = sign_envelope(attester, &envelope);
        Attestation {
            // attestation_id is `::uuid`-cast on the PG write path — use a
            // real UUID (project_test_fixtures_uuid_vs_uuid_like); `id` is
            // carried in the signed envelope for per-case uniqueness.
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: attester.to_owned(),
            attested_key_id: attested.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: Some(1.0),
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            scrub_key_id: attester.to_owned(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: Some(chrono::Utc::now()),
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: if tier == attestation_tier::LOCAL {
                cohort_scope::SELF.to_owned()
            } else {
                attestation_tier::FEDERATION.to_owned()
            },
            tier: tier.to_owned(),
            promoted_at: None,
        }
    }

    /// The full CC 5.3.2.4.3.1 ingest-gate matrix, backend-agnostic — runs
    /// directly against a [`FederationDirectory`] so it covers the memory
    /// backend too (it runs there in production), not only the engine-wrapped
    /// sqlite + postgres backends.
    async fn run_tier_ingest_matrix(dir: &dyn FederationDirectory, tag: &str) {
        let attester = format!("ti-attester-{tag}");
        let attested = format!("ti-attested-{tag}");
        register_hybrid_key(dir, &attester).await;
        register_hybrid_key(dir, &attested).await;

        // (a) federation-tier with a VALID hybrid sig → ADMITTED + readable.
        let a = att(
            &attester,
            &attested,
            &format!("ti-a-{tag}"),
            attestation_tier::FEDERATION,
        );
        let a_id = a.attestation_id.clone();
        dir.put_attestation(SignedAttestation { attestation: a })
            .await
            .expect("(a) valid hybrid federation-tier row must be admitted");
        let by = dir.list_attestations_by(&attester).await.expect("list");
        assert!(
            by.iter().any(|r| r.attestation_id == a_id),
            "(a) admitted row must be readable"
        );

        // (b) federation-tier with the ML-DSA-65 half MISSING (classical-
        // only) → REJECTED + NOT stored. THE load-bearing CC 5.3.2.4.3.1 guard.
        let mut b = att(
            &attester,
            &attested,
            &format!("ti-b-{tag}"),
            attestation_tier::FEDERATION,
        );
        let b_id = b.attestation_id.clone();
        b.scrub_signature_pqc = None; // drop the PQC half
        b.pqc_completed_at = None;
        let err = dir
            .put_attestation(SignedAttestation { attestation: b })
            .await
            .expect_err("(b) classical-only federation-tier row must be REJECTED");
        assert_eq!(
            err.kind(),
            "federation_federation_tier_unverified",
            "(b) rejection must be the tier-ingest gate"
        );
        assert!(
            dir.get_attestation(&b_id).await.expect("get").is_none(),
            "(b) rejected row must NOT be stored (fail-secure)"
        );

        // (c) federation-tier with a TAMPERED ML-DSA-65 half → REJECTED.
        let mut c = att(
            &attester,
            &attested,
            &format!("ti-c-{tag}"),
            attestation_tier::FEDERATION,
        );
        let c_id = c.attestation_id.clone();
        // Re-sign a DIFFERENT envelope to get a valid-length-but-wrong PQC
        // sig, then keep the original envelope/hash → the PQC half no
        // longer verifies over the real bound input.
        let (_, _, wrong_pqc) = sign_envelope(
            &attester,
            &serde_json::json!({ "id": "not-the-real-envelope" }),
        );
        c.scrub_signature_pqc = wrong_pqc;
        let err = dir
            .put_attestation(SignedAttestation { attestation: c })
            .await
            .expect_err("(c) tampered ML-DSA-65 must be REJECTED");
        assert_eq!(err.kind(), "federation_federation_tier_unverified");
        assert!(dir.get_attestation(&c_id).await.expect("get").is_none());

        // (d) federation-tier from an UNREGISTERED attester → REJECTED
        // (no pubkeys to verify against). On the postgres/sqlite backends
        // the FK check also rejects an unknown attester, but the tier-
        // ingest gate (which runs there too, with the resolved-but-here
        // unregistered key) fails first with its own typed error on the
        // memory backend ordering; either way the row is not stored. We
        // assert non-storage + a rejection.
        let unreg = format!("ti-unreg-{tag}");
        let d = att(
            &unreg,
            &attested,
            &format!("ti-d-{tag}"),
            attestation_tier::FEDERATION,
        );
        let d_id = d.attestation_id.clone();
        let err = dir
            .put_attestation(SignedAttestation { attestation: d })
            .await
            .expect_err("(d) unregistered attester must be REJECTED");
        // The ingest gate's own rejection token (when it fires) or the
        // FK InvalidArgument (when the backend's FK check fires first) —
        // both are fail-secure non-stores.
        assert!(
            err.kind() == "federation_federation_tier_unverified"
                || err.kind() == "federation_invalid_argument",
            "(d) unexpected rejection kind: {}",
            err.kind()
        );
        assert!(dir.get_attestation(&d_id).await.expect("get").is_none());

        // (e) LOCAL-tier row WITHOUT a PQC half → ADMITTED (the exemption;
        // proves we don't over-reject local-tier). cohort_scope=self is
        // required at local tier by the existing v4.0 read-gate.
        let mut e = att(
            &attester,
            &attester,
            &format!("ti-e-{tag}"),
            attestation_tier::LOCAL,
        );
        let e_id = e.attestation_id.clone();
        e.scrub_signature_pqc = None; // local-tier may defer the signature
        e.pqc_completed_at = None;
        dir.put_attestation(SignedAttestation { attestation: e })
            .await
            .expect("(e) local-tier row without PQC must be ADMITTED (CC 5.3.2.2 exemption)");
        assert!(
            dir.get_attestation(&e_id).await.expect("get").is_some(),
            "(e) admitted local-tier row must be stored"
        );
    }

    /// QualReview (LOW): the gate runs on the MEMORY backend in production
    /// (`put_attestation` calls `verify_federation_tier_ingest`), so test the
    /// matrix directly against it too — no engine DSN dispatches to memory.
    #[tokio::test]
    async fn tier_ingest_matrix_memory() {
        let backend = crate::store::memory::MemoryBackend::new();
        run_tier_ingest_matrix(&backend, "memory").await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn tier_ingest_matrix_sqlite() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct sqlite engine");
        let dir = engine.federation_directory();
        run_tier_ingest_matrix(&*dir, "sqlite").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn tier_ingest_matrix_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping tier_ingest_matrix_postgres: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let engine = Engine::with_signer(test_signer(), &dsn)
            .await
            .expect("construct postgres engine");
        let tag = format!("pg-{}", uuid::Uuid::new_v4().simple());
        let dir = engine.federation_directory();
        run_tier_ingest_matrix(&*dir, &tag).await;
    }
}
