//! Hybrid Ed25519 + ML-DSA-65 verify primitive (CIRISPersist#14).
//!
//! v0.3.6 — closes the [CIRISEdge OQ-11] day-1 hybrid posture
//! requirement by exposing `verify_hybrid` on the `Engine` surface.
//! The cryptographic primitive lives in
//! `ciris_crypto::HybridVerifier`; this module is the policy layer
//! + persist's contract for arbitrary canonical bytes.
//!
//! # Why persist owns this
//!
//! Verify-via-persist is the federation's single-source-of-truth
//! per [CIRISPersist#7]. Edge calling `ciris_crypto::HybridVerifier`
//! directly would:
//!
//! - Duplicate the verify call site (edge's verify + persist's
//!   `receive_and_persist` would both verify, with drift risk)
//! - Create a second canonicalization expectation
//! - Bypass the policy machinery, which is per-deployment and most
//!   naturally lives next to the `federation_keys` directory persist
//!   already owns
//!
//! Same closure pattern that applied to `canonicalize_envelope` and
//! `lookup_public_key`.
//!
//! # Policy
//!
//! [`HybridPolicy`] picks the federation peer's hybrid posture:
//!
//! - `Strict` — reject hybrid-pending rows (ml_dsa_65_sig is None)
//! - `SoftFreshness { window }` — accept hybrid-pending if
//!   `row_age < window` (the row was written recently enough that
//!   the cold-path PQC sweep hasn't yet had time to hybrid-complete
//!   it; matches V004's eventual-consistency contract)
//! - `Ed25519Fallback` — always accept Ed25519-only verification
//!
//! [CIRISEdge OQ-11]: https://github.com/CIRISAI/CIRISEdge
//! [CIRISPersist#7]: https://github.com/CIRISAI/CIRISPersist/issues/7

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_crypto::{
    ClassicalAlgorithm, CryptoKind, Ed25519Verifier, HybridSignature, HybridVerifier,
    MlDsa65Verifier, PqcAlgorithm, SignatureMode, TaggedClassicalSignature, TaggedPqcSignature,
    CRYPTO_KIND_CIRIS_V1,
};

/// Hybrid-verify policy. Picks how a peer treats hybrid-pending rows
/// (rows where the cold-path ML-DSA-65 sign hasn't yet completed).
///
/// Per CIRISEdge OQ-11 closure: federation peers configure this per
/// trust-level. Strict for high-stakes domains; SoftFreshness for
/// general-purpose with bounded soft-PQC window; Ed25519Fallback for
/// development / sovereign-mode where the cold-path may never run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HybridPolicy {
    /// Reject hybrid-pending rows. Both signatures REQUIRED.
    /// Production posture for high-stakes domains.
    Strict,
    /// Accept hybrid-pending rows iff `row_age < window`. Matches
    /// V004's eventual-consistency contract: a row written recently
    /// enough that the cold-path sweep hasn't had time to fill in
    /// the PQC component is acceptable.
    SoftFreshness {
        /// Maximum acceptable age of a hybrid-pending row.
        window: Duration,
    },
    /// Always accept Ed25519-only verification. Development /
    /// sovereign-mode posture; not for federation production.
    ///
    /// # v37.0.0 — the production callers are gone, with two exceptions
    ///
    /// The v37.0.0 break flipped every production path that could
    /// meaningfully verify hybrid to [`Strict`](Self::Strict): the edge
    /// pipeline ingest route, the secrets routes, and
    /// `put_delivery_attestation` on BOTH the sqlite and postgres
    /// cirisnode backends.
    ///
    /// Two callers deliberately remain, and they are PINS rather than
    /// leftovers — in both, the PQC **pubkey** argument is a hardcoded
    /// `None`, so `Strict` would refuse every input rather than tighten
    /// anything:
    ///
    /// * [`crate::audit::verify::verify_entry_signature`] — `AuditEntry`
    ///   has no PQC field and `actor_id` IS the Ed25519 pubkey. Measured:
    ///   flipping it reds 19 tests and takes the stored audit chain +
    ///   Merkle corpus dark.
    /// * `crate::cirisnode::verify::verify_envelope_signed` — no
    ///   per-contributor ML-DSA-65 pubkey directory exists on that track.
    ///
    /// Both carry the reasoning at their definition. Tightening either is
    /// a plumbing change (give the plane a PQC pubkey source) first and a
    /// policy change second — never a one-line edit here.
    ///
    /// # v61.1.0 (CIRISPersist#1233) — not reachable from any caller surface
    ///
    /// The public Rust [`verify_hybrid`] and [`verify_hybrid_via_directory`],
    /// the Python doors and the capsule's `VerifyHybridViaDirectory` refuse
    /// this variant (and `SoftFreshness`) with [`VERIFY_POLICY_VIOLATION`]
    /// (CC 5.3.2.4.3.1). The two pins above reach it through the
    /// crate-private twin `verify_hybrid_with_policy`. Per CC's reading, the
    /// audit pin is not a gap (the audit plane's gate is its hybrid-signed
    /// tree head, CC 5.3.1); the cirisnode pin is, and closes in v62 with the
    /// variant itself.
    Ed25519Fallback,
}

/// Outcome of a successful `verify_hybrid` call. Distinguishes
/// hybrid-verified (both signatures passed) from Ed25519-only
/// (PQC absent, accepted by policy).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VerifyOutcome {
    /// Both Ed25519 and ML-DSA-65 signatures verified.
    HybridVerified,
    /// Only Ed25519 verified — `ml_dsa_65_sig` was `None` and policy
    /// is `SoftFreshness` with `row_age < window`. The `row_age` is
    /// echoed back so the caller can log/audit which window matched.
    Ed25519VerifiedHybridPending {
        /// Age of the row at the time of verification, as passed by
        /// the caller. `None` if the caller didn't supply row_age.
        row_age: Option<Duration>,
    },
    /// Only Ed25519 verified — `ml_dsa_65_sig` was `None` and policy
    /// is `Ed25519Fallback`. Distinct from
    /// `Ed25519VerifiedHybridPending` so audit logs can tell whether
    /// the acceptance was bounded-soft or always-soft.
    Ed25519VerifiedFallback,
}

/// Errors from `verify_hybrid`.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// `ml_dsa_65_sig_b64` was None and policy is `Strict`.
    #[error("hybrid-pending row rejected by Strict policy")]
    HybridPendingRejected,

    /// `ml_dsa_65_sig_b64` was None, policy is `SoftFreshness`, but
    /// `row_age` was either not supplied or exceeds `window`.
    #[error(
        "hybrid-pending row rejected by SoftFreshness (row_age {row_age:?}, window {window:?})"
    )]
    SoftFreshnessExpired {
        /// Row age the caller supplied (or `None` if unsupplied).
        row_age: Option<Duration>,
        /// Configured window from the policy.
        window: Duration,
    },

    /// `ml_dsa_65_sig_b64` was Some but `ml_dsa_65_pubkey_b64` was None
    /// (or vice versa). Both PQC fields must be present together.
    #[error("PQC signature without pubkey (or vice versa) — both required")]
    PqcFieldsMustBeBoth,

    /// Base64 decode of one of the input strings failed.
    #[error("base64 decode {field}: {source}")]
    Base64 {
        /// Which field failed decode.
        field: &'static str,
        /// Underlying decode error.
        source: base64::DecodeError,
    },

    /// Length validation failed (Ed25519 sig: 64, pubkey: 32;
    /// ML-DSA-65 sig: 3309, pubkey: 1952).
    #[error("invalid length for {field}: got {got}, expected {expected}")]
    InvalidLength {
        /// Which field had a wrong length.
        field: &'static str,
        /// Observed length.
        got: usize,
        /// Spec-required length.
        expected: usize,
    },

    /// `ciris_crypto::HybridVerifier::verify` returned an error
    /// (signature mismatch, unsupported crypto kind, etc.). Wraps the
    /// underlying CryptoError as a string so it crosses module
    /// boundaries cleanly.
    #[error("crypto: {0}")]
    Crypto(String),

    /// v61.1.0 (CIRISPersist#1233, CC 5.3.2.4.3.1) — a caller handed a
    /// public verify door ([`verify_hybrid`], [`verify_hybrid_via_directory`],
    /// [`crate::verify::ed25519::verify_trace_hybrid`], the PyO3 doors, the
    /// capsule op) a policy other than [`HybridPolicy::Strict`]. Refused by
    /// [`require_strict_policy`] before any decode, lookup or crypto. The
    /// message leads with [`VERIFY_POLICY_VIOLATION`].
    #[error(
        "{}: policy {policy:?} refused; hybrid-required (Strict) \
         is the only verifier policy (CC 5.3.2.4.3.1; CIRISPersist#1233)",
        VERIFY_POLICY_VIOLATION
    )]
    PolicyViolation {
        /// The refused policy, as the caller passed it.
        policy: HybridPolicy,
    },
}

impl VerifyError {
    /// Stable string-token for telemetry / structured logging.
    /// Same shape as the rest of persist's error tokens
    /// (THREAT_MODEL.md AV-15).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::HybridPendingRejected => "verify_hybrid_pending_rejected",
            Self::SoftFreshnessExpired { .. } => "verify_hybrid_soft_freshness_expired",
            Self::PqcFieldsMustBeBoth => "verify_hybrid_pqc_fields_mismatch",
            Self::Base64 { .. } => "verify_hybrid_base64",
            Self::InvalidLength { .. } => "verify_hybrid_invalid_length",
            Self::Crypto(_) => "verify_hybrid_crypto",
            Self::PolicyViolation { .. } => VERIFY_POLICY_VIOLATION,
        }
    }
}

/// v61.1.0 (CIRISPersist#1233, CC 5.3.2.4.3.1) — the stable token every
/// caller-facing verify door raises when it is handed a policy other than
/// hybrid-required.
///
/// CC 5.3.2.4.3.1: "no classical-only, no hybrid-pending accommodation … a
/// verifier's hybrid-required check is always-on, never an operator toggle".
/// Every door that still carries a `policy` argument keeps it until v62
/// removes it, and refuses every value except `"strict"` /
/// [`HybridPolicy::Strict`] with this token BEFORE any decode, lookup or
/// crypto runs: the public Rust [`verify_hybrid`],
/// [`verify_hybrid_via_directory`] and
/// [`crate::verify::ed25519::verify_trace_hybrid`] (which calls
/// `verify_hybrid`), `Engine.verify_hybrid`,
/// `Engine.verify_hybrid_via_directory` and the three `verify_signed_*`
/// methods that route through it, and the directory capsule's
/// `VerifyHybridViaDirectory` op. All of them ask [`require_strict_policy`].
pub const VERIFY_POLICY_VIOLATION: &str = "verify_policy_violation";

/// v61.1.0 (CIRISPersist#1233) — **the one hybrid-required check.**
/// `Strict` passes; every other variant is refused with
/// [`VerifyError::PolicyViolation`], whose message and
/// [`kind`](VerifyError::kind) lead with [`VERIFY_POLICY_VIOLATION`].
///
/// Every caller-facing verify path passes through it: the public
/// [`verify_hybrid`] and [`verify_hybrid_via_directory`] call it first (so
/// the capsule's `VerifyHybridViaDirectory` arm, which calls the latter,
/// meets it before the directory lookup), `verify_trace_hybrid` calls it
/// before canonicalizing, and the PyO3 `parse_hybrid_policy` calls it on the
/// policy it decodes from the string (an unknown string is a malformed
/// policy and is refused with the same token before it gets that far).
///
/// Persist's own two classical-only planes (`audit::verify` and
/// `cirisnode::verify`) do NOT pass through it: they call the crate-private
/// twin `verify_hybrid_with_policy`; see their PINNED notes.
///
/// # Errors
///
/// [`VerifyError::PolicyViolation`] for any policy other than
/// [`HybridPolicy::Strict`].
pub fn require_strict_policy(policy: &HybridPolicy) -> Result<(), VerifyError> {
    match policy {
        HybridPolicy::Strict => Ok(()),
        other => Err(VerifyError::PolicyViolation { policy: *other }),
    }
}

/// Expected raw lengths for each component (post-base64-decode):
/// Ed25519 signature 64 bytes, Ed25519 pubkey 32 bytes,
/// ML-DSA-65 signature 3309 bytes (FIPS 204 final),
/// ML-DSA-65 pubkey 1952 bytes.
const ED25519_SIG_LEN: usize = 64;
const ED25519_PUBKEY_LEN: usize = 32;
const ML_DSA_65_SIG_LEN: usize = 3309;
const ML_DSA_65_PUBKEY_LEN: usize = 1952;

fn decode_b64_fixed(
    b64: &str,
    field: &'static str,
    expected: usize,
) -> Result<Vec<u8>, VerifyError> {
    let bytes = BASE64
        .decode(b64)
        .map_err(|source| VerifyError::Base64 { field, source })?;
    if bytes.len() != expected {
        return Err(VerifyError::InvalidLength {
            field,
            got: bytes.len(),
            expected,
        });
    }
    Ok(bytes)
}

/// v0.3.6 (CIRISPersist#14) — Verify a hybrid Ed25519 + ML-DSA-65
/// signature over arbitrary canonical bytes.
///
/// # v61.1.0 (CIRISPersist#1233, CC 5.3.2.4.3.1) — `Strict` only
///
/// `policy` must be [`HybridPolicy::Strict`]: any other variant is refused
/// with [`VerifyError::PolicyViolation`] ([`VERIFY_POLICY_VIOLATION`]) by
/// [`require_strict_policy`], before any decode or crypto. The argument stays
/// until v62 removes it. A hybrid-pending input (both PQC arguments `None`)
/// is then refused as [`VerifyError::HybridPendingRejected`].
///
/// `ml_dsa_65_sig_b64` and `ml_dsa_65_pubkey_b64` are paired: either
/// both Some (full hybrid verify) or both None (the row is
/// hybrid-pending; acceptance depends on `policy`).
///
/// `row_age` is consulted only by `HybridPolicy::SoftFreshness`. Other
/// policies ignore it. Pass `None` if the caller doesn't have a
/// `pqc_completed_at` reference (typical for non-federation-keys
/// inputs); SoftFreshness will then reject as
/// `SoftFreshnessExpired { row_age: None }`.
pub fn verify_hybrid(
    canonical_bytes: &[u8],
    ed25519_sig_b64: &str,
    ml_dsa_65_sig_b64: Option<&str>,
    ed25519_pubkey_b64: &str,
    ml_dsa_65_pubkey_b64: Option<&str>,
    policy: HybridPolicy,
    row_age: Option<Duration>,
) -> Result<VerifyOutcome, VerifyError> {
    require_strict_policy(&policy)?;
    verify_hybrid_with_policy(
        canonical_bytes,
        ed25519_sig_b64,
        ml_dsa_65_sig_b64,
        ed25519_pubkey_b64,
        ml_dsa_65_pubkey_b64,
        policy,
        row_age,
    )
}

/// v61.1.0 (CIRISPersist#1233) — the policy-taking twin of [`verify_hybrid`],
/// crate-private. It does NOT ask [`require_strict_policy`]: `policy` decides
/// how a hybrid-pending input is treated (see [`HybridPolicy`]).
///
/// Exactly two production callers pass anything but `Strict`, and both are
/// PINNED classical-only planes whose PQC pubkey argument is a hardcoded
/// `None`: `audit::verify::verify_entry_signature` (an entry's inner
/// signature; the audit plane's gate is the hybrid-signed head, CC 5.3.1)
/// and `cirisnode::verify::verify_envelope_signed` (non-conformant until
/// v62). No caller surface reaches this function with a policy of its own.
pub(crate) fn verify_hybrid_with_policy(
    canonical_bytes: &[u8],
    ed25519_sig_b64: &str,
    ml_dsa_65_sig_b64: Option<&str>,
    ed25519_pubkey_b64: &str,
    ml_dsa_65_pubkey_b64: Option<&str>,
    policy: HybridPolicy,
    row_age: Option<Duration>,
) -> Result<VerifyOutcome, VerifyError> {
    // Pair PQC sig + pubkey: both-or-neither. Catching the mismatch
    // here gives a clearer error than a downstream Crypto failure.
    let pqc_pair = match (ml_dsa_65_sig_b64, ml_dsa_65_pubkey_b64) {
        (Some(sig), Some(pk)) => Some((sig, pk)),
        (None, None) => None,
        _ => return Err(VerifyError::PqcFieldsMustBeBoth),
    };

    // Decode + length-validate the always-required Ed25519 components.
    let ed25519_sig = decode_b64_fixed(ed25519_sig_b64, "ed25519_sig", ED25519_SIG_LEN)?;
    let ed25519_pubkey =
        decode_b64_fixed(ed25519_pubkey_b64, "ed25519_pubkey", ED25519_PUBKEY_LEN)?;

    match pqc_pair {
        Some((pqc_sig_b64, pqc_pk_b64)) => {
            // Full hybrid verify path. Decode PQC components, build a
            // HybridSignature, hand to HybridVerifier::verify.
            let pqc_sig = decode_b64_fixed(pqc_sig_b64, "ml_dsa_65_sig", ML_DSA_65_SIG_LEN)?;
            let pqc_pk = decode_b64_fixed(pqc_pk_b64, "ml_dsa_65_pubkey", ML_DSA_65_PUBKEY_LEN)?;

            let signature = HybridSignature {
                crypto_kind: CRYPTO_KIND_CIRIS_V1,
                classical: TaggedClassicalSignature {
                    algorithm: ClassicalAlgorithm::Ed25519,
                    signature: ed25519_sig,
                    public_key: ed25519_pubkey,
                },
                pqc: TaggedPqcSignature {
                    algorithm: PqcAlgorithm::MlDsa65,
                    signature: pqc_sig,
                    public_key: pqc_pk,
                },
                mode: SignatureMode::HybridRequired,
            };

            let verifier = HybridVerifier::with_expected_crypto_kind(
                Ed25519Verifier,
                MlDsa65Verifier::new(),
                CryptoKind::from(CRYPTO_KIND_CIRIS_V1),
            );

            verifier
                .verify(canonical_bytes, &signature)
                .map_err(|e| VerifyError::Crypto(format!("{e}")))?;
            Ok(VerifyOutcome::HybridVerified)
        }
        None => verify_ed25519_only_with_policy(
            canonical_bytes,
            &ed25519_sig,
            &ed25519_pubkey,
            policy,
            row_age,
        ),
    }
}

/// v0.4.1 (CIRISEdge ask) — `verify_hybrid` with internal directory
/// lookup. Generic over `FederationDirectory` so callers can compose
/// against any backend (postgres, sqlite, memory, future) without
/// committing to a concrete type.
///
/// Persist's PyO3 `Engine.verify_hybrid_via_directory` wraps this
/// function; consumers of the Rust API call this directly. **One
/// implementation, both surfaces** — the CIRISPersist#7 single-
/// source-of-truth pattern.
///
/// Returns `VerifyError::Crypto("verify_unknown_key")` when the
/// directory has no record of `signing_key_id` (matches the PyO3
/// surface's stable error token for downstream HTTP layer mapping).
///
/// `signing_key_id` resolution: looks up the row in `federation_keys`
/// via `FederationDirectory::lookup_public_key`. Both pubkeys
/// (Ed25519 mandatory, ML-DSA-65 optional during hybrid-pending
/// window) are pulled from the row.
///
/// v61.1.0 (CIRISPersist#1233, CC 5.3.2.4.3.1) — `policy` must be
/// [`HybridPolicy::Strict`]: any other variant is refused with
/// [`VerifyError::PolicyViolation`] by [`require_strict_policy`] BEFORE the
/// directory lookup, so an unknown key under a non-strict policy is a policy
/// refusal, not `verify_unknown_key`. A hybrid-pending row is then refused as
/// [`VerifyError::HybridPendingRejected`].
pub async fn verify_hybrid_via_directory<F>(
    directory: &F,
    canonical_bytes: &[u8],
    signing_key_id: &str,
    ed25519_sig_b64: &str,
    ml_dsa_65_sig_b64: Option<&str>,
    policy: HybridPolicy,
    row_age: Option<Duration>,
) -> Result<VerifyOutcome, VerifyError>
where
    // `?Sized` so `&dyn FederationDirectory` (e.g. the ABI-stable
    // `directory_ops_capsule` dispatcher, CIRISPersist#320) can call this
    // directly, not just concrete backends. Existing `&ConcreteBackend`
    // callers are unaffected.
    F: crate::federation::FederationDirectory + ?Sized,
{
    require_strict_policy(&policy)?;
    let key_record = directory
        .lookup_public_key(signing_key_id)
        .await
        .map_err(|e| VerifyError::Crypto(format!("federation directory lookup: {e}")))?
        .ok_or_else(|| VerifyError::Crypto("verify_unknown_key".to_string()))?;

    // The policy was asked above, before the lookup; the twin does not ask
    // again.
    verify_hybrid_with_policy(
        canonical_bytes,
        ed25519_sig_b64,
        ml_dsa_65_sig_b64,
        &key_record.pubkey_ed25519_base64,
        key_record.pubkey_ml_dsa_65_base64.as_deref(),
        policy,
        row_age,
    )
}

/// Hybrid-pending path: only Ed25519 is available. Policy decides
/// whether to accept and which `VerifyOutcome` variant lands.
fn verify_ed25519_only_with_policy(
    canonical_bytes: &[u8],
    ed25519_sig: &[u8],
    ed25519_pubkey: &[u8],
    policy: HybridPolicy,
    row_age: Option<Duration>,
) -> Result<VerifyOutcome, VerifyError> {
    // Run the Ed25519 verification first regardless of policy — a
    // forged Ed25519 signature should reject as Crypto, not
    // HybridPendingRejected. (Policy gates ACCEPTANCE, not rejection.)
    //
    // v49.0.0 (CIRISPersist#913) — STRICT, and stated. CIRISVerify v17.0.0
    // made `ClassicalVerifier::verify` strict for Ed25519, but this call site
    // names the rule rather than inheriting it: permissive (cofactorless)
    // verification accepts a small-order `A`/`R`, so `(R = identity, s = 0)`
    // verifies any message against the identity key with no private key in
    // existence. The ML-DSA-65 half under `HybridPolicy::Strict` already
    // contained that on the federation tier; this closes it on the classical
    // half itself, the same rule the trace floor (`verify/ed25519.rs`) uses.
    let ed25519_verifier = Ed25519Verifier;
    let ok = ed25519_verifier
        .verify_strict(ed25519_pubkey, canonical_bytes, ed25519_sig)
        .map_err(|e| VerifyError::Crypto(format!("ed25519: {e}")))?;
    if !ok {
        return Err(VerifyError::Crypto(
            "ed25519 signature mismatch".to_string(),
        ));
    }

    // Ed25519 verified. Apply policy.
    match policy {
        HybridPolicy::Strict => Err(VerifyError::HybridPendingRejected),
        HybridPolicy::Ed25519Fallback => Ok(VerifyOutcome::Ed25519VerifiedFallback),
        HybridPolicy::SoftFreshness { window } => match row_age {
            Some(age) if age < window => {
                Ok(VerifyOutcome::Ed25519VerifiedHybridPending { row_age: Some(age) })
            }
            _ => Err(VerifyError::SoftFreshnessExpired { row_age, window }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use ed25519_dalek::Signer as _;

    fn ed25519_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0xCE; 32])
    }

    fn ml_dsa_signer() -> ciris_keyring::MlDsa65SoftwareSigner {
        // Deterministic seed for tests.
        ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&[0x42; 32], "test-mldsa")
            .expect("seed length checked")
    }

    /// Ed25519 alone is the universal first step. Test the
    /// hybrid-pending paths here against synthesized signatures.
    fn ed25519_pubkey_b64() -> String {
        B64.encode(ed25519_signing_key().verifying_key().to_bytes())
    }

    fn ed25519_sig_b64(canonical: &[u8]) -> String {
        let sk = ed25519_signing_key();
        B64.encode(sk.sign(canonical).to_bytes())
    }

    // v61.1.0 (CIRISPersist#1233) — the `Ed25519Fallback` / `SoftFreshness`
    // tests below exercise the policy machinery through the crate-private
    // twin, which the two PINNED classical-only planes call; the public
    // `verify_hybrid` refuses those policies (I1568 below).

    /// v61.1.0 (CIRISPersist#1233, CC 5.3.2.4.3.1) — **I1568 (unit leg): the
    /// public `verify_hybrid` refuses every policy but `Strict`.** A VALID
    /// classical-only signature is exactly the input `Ed25519Fallback` and an
    /// in-window `SoftFreshness` accept through the twin, so the refusal is
    /// the policy gate. Garbage base64 under a non-strict policy is refused
    /// with the policy token, not `verify_hybrid_base64`: the gate runs
    /// before any decode. Under `Strict` the same garbage reaches the
    /// decoder (the control).
    #[test]
    fn i1568_public_verify_hybrid_refuses_every_policy_but_strict() {
        let canonical = b"CIRISPersist#1233 I1568";
        for policy in [
            HybridPolicy::Ed25519Fallback,
            HybridPolicy::SoftFreshness {
                window: Duration::from_secs(86_400),
            },
        ] {
            let accepted_by_the_twin = verify_hybrid_with_policy(
                canonical,
                &ed25519_sig_b64(canonical),
                None,
                &ed25519_pubkey_b64(),
                None,
                policy,
                Some(Duration::from_secs(1)),
            );
            assert!(
                accepted_by_the_twin.is_ok(),
                "I1568 fixture: the twin accepts {policy:?}: {accepted_by_the_twin:?}"
            );
            let err = verify_hybrid(
                canonical,
                &ed25519_sig_b64(canonical),
                None,
                &ed25519_pubkey_b64(),
                None,
                policy,
                Some(Duration::from_secs(1)),
            )
            .expect_err("I1568: the public verify_hybrid refuses a non-strict policy");
            assert!(
                matches!(err, VerifyError::PolicyViolation { policy: p } if p == policy),
                "I1568: {policy:?} is a policy violation: {err:?}"
            );
            assert_eq!(err.kind(), VERIFY_POLICY_VIOLATION);
            assert!(
                err.to_string().starts_with(VERIFY_POLICY_VIOLATION),
                "I1568: the message leads with the token: {err}"
            );

            let err = verify_hybrid(
                canonical,
                "!!!not-base64!!!",
                None,
                "!!!",
                None,
                policy,
                None,
            )
            .expect_err("I1568: garbage under a non-strict policy");
            assert_eq!(
                err.kind(),
                VERIFY_POLICY_VIOLATION,
                "I1568: {policy:?} is refused before any decode: {err:?}"
            );
        }
        let err = verify_hybrid(
            canonical,
            "!!!not-base64!!!",
            None,
            "!!!",
            None,
            HybridPolicy::Strict,
            None,
        )
        .expect_err("I1568: garbage under Strict");
        assert_eq!(
            err.kind(),
            "verify_hybrid_base64",
            "I1568: under Strict the garbage reaches the decoder"
        );
        assert!(require_strict_policy(&HybridPolicy::Strict).is_ok());
    }

    /// v0.3.6 — hybrid-pending row + Strict policy → rejects.
    #[test]
    fn strict_rejects_hybrid_pending() {
        let canonical = b"some-canonical-bytes";
        let err = verify_hybrid(
            canonical,
            &ed25519_sig_b64(canonical),
            None,
            &ed25519_pubkey_b64(),
            None,
            HybridPolicy::Strict,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, VerifyError::HybridPendingRejected));
        assert_eq!(err.kind(), "verify_hybrid_pending_rejected");
    }

    /// v0.3.6 — hybrid-pending + Ed25519Fallback → accepts.
    #[test]
    fn fallback_accepts_hybrid_pending() {
        let canonical = b"some-canonical-bytes";
        let outcome = verify_hybrid_with_policy(
            canonical,
            &ed25519_sig_b64(canonical),
            None,
            &ed25519_pubkey_b64(),
            None,
            HybridPolicy::Ed25519Fallback,
            None,
        )
        .unwrap();
        assert_eq!(outcome, VerifyOutcome::Ed25519VerifiedFallback);
    }

    /// v0.3.6 — hybrid-pending + SoftFreshness within window → accepts.
    #[test]
    fn soft_freshness_within_window_accepts() {
        let canonical = b"some-canonical-bytes";
        let outcome = verify_hybrid_with_policy(
            canonical,
            &ed25519_sig_b64(canonical),
            None,
            &ed25519_pubkey_b64(),
            None,
            HybridPolicy::SoftFreshness {
                window: Duration::from_secs(60),
            },
            Some(Duration::from_secs(10)),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            VerifyOutcome::Ed25519VerifiedHybridPending { row_age: Some(_) }
        ));
    }

    /// v0.3.6 — hybrid-pending + SoftFreshness past window → rejects.
    #[test]
    fn soft_freshness_past_window_rejects() {
        let canonical = b"some-canonical-bytes";
        let err = verify_hybrid_with_policy(
            canonical,
            &ed25519_sig_b64(canonical),
            None,
            &ed25519_pubkey_b64(),
            None,
            HybridPolicy::SoftFreshness {
                window: Duration::from_secs(60),
            },
            Some(Duration::from_secs(120)),
        )
        .unwrap_err();
        assert!(matches!(err, VerifyError::SoftFreshnessExpired { .. }));
    }

    /// v0.3.6 — SoftFreshness with no row_age supplied → rejects (the
    /// caller MUST pass row_age for SoftFreshness to grant acceptance).
    #[test]
    fn soft_freshness_no_row_age_rejects() {
        let canonical = b"some-canonical-bytes";
        let err = verify_hybrid_with_policy(
            canonical,
            &ed25519_sig_b64(canonical),
            None,
            &ed25519_pubkey_b64(),
            None,
            HybridPolicy::SoftFreshness {
                window: Duration::from_secs(60),
            },
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            VerifyError::SoftFreshnessExpired { row_age: None, .. }
        ));
    }

    /// v0.3.6 — PQC sig without pubkey rejects as PqcFieldsMustBeBoth.
    #[test]
    fn pqc_sig_without_pubkey_rejects() {
        let canonical = b"some-canonical-bytes";
        let err = verify_hybrid(
            canonical,
            &ed25519_sig_b64(canonical),
            Some("AAAA"),
            &ed25519_pubkey_b64(),
            None,
            HybridPolicy::Strict,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, VerifyError::PqcFieldsMustBeBoth));
    }

    /// v0.3.6 — full hybrid round-trip. Sign with both Ed25519 and
    /// ML-DSA-65; verify_hybrid in Strict mode returns HybridVerified.
    /// Bound signature: PQC signs (canonical || classical_sig).
    #[tokio::test]
    async fn hybrid_round_trip_strict() {
        use ciris_keyring::PqcSigner;
        let canonical = b"some-canonical-bytes-for-hybrid";

        // Classical sign.
        let sk = ed25519_signing_key();
        let ed25519_sig = sk.sign(canonical);
        let ed25519_sig_bytes = ed25519_sig.to_bytes();

        // PQC sign over (canonical || classical_sig).
        let mut bound = Vec::with_capacity(canonical.len() + ed25519_sig_bytes.len());
        bound.extend_from_slice(canonical);
        bound.extend_from_slice(&ed25519_sig_bytes);
        let mldsa = ml_dsa_signer();
        let pqc_sig = mldsa.sign(&bound).await.expect("ml-dsa sign");
        let pqc_pk = mldsa.public_key().await.expect("ml-dsa pk");

        let outcome = verify_hybrid(
            canonical,
            &B64.encode(ed25519_sig_bytes),
            Some(&B64.encode(&pqc_sig)),
            &ed25519_pubkey_b64(),
            Some(&B64.encode(&pqc_pk)),
            HybridPolicy::Strict,
            None,
        )
        .expect("hybrid verify");
        assert_eq!(outcome, VerifyOutcome::HybridVerified);
    }

    /// v0.3.6 — full hybrid with tampered canonical bytes rejects.
    #[tokio::test]
    async fn hybrid_tampered_canonical_rejects() {
        use ciris_keyring::PqcSigner;
        let canonical = b"original-canonical-bytes";

        let sk = ed25519_signing_key();
        let ed25519_sig = sk.sign(canonical);
        let ed25519_sig_bytes = ed25519_sig.to_bytes();

        let mut bound = Vec::with_capacity(canonical.len() + ed25519_sig_bytes.len());
        bound.extend_from_slice(canonical);
        bound.extend_from_slice(&ed25519_sig_bytes);
        let mldsa = ml_dsa_signer();
        let pqc_sig = mldsa.sign(&bound).await.expect("ml-dsa sign");
        let pqc_pk = mldsa.public_key().await.expect("ml-dsa pk");

        let tampered = b"tampered-canonical-bytes";
        let err = verify_hybrid(
            tampered,
            &B64.encode(ed25519_sig_bytes),
            Some(&B64.encode(&pqc_sig)),
            &ed25519_pubkey_b64(),
            Some(&B64.encode(&pqc_pk)),
            HybridPolicy::Strict,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, VerifyError::Crypto(_)));
    }
}
