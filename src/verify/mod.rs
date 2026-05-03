//! Signature verification + canonical bytes (TRACE_WIRE_FORMAT.md §8).
//!
//! Mission alignment (MISSION.md §2 — `verify/`): signature
//! verification is the cryptographic floor of the Coherent
//! Intersection Hypothesis. Every persisted row must have been
//! provably produced by the claimed agent at the claimed moment, OR
//! be explicitly marked unverified. There is no third state.
//!
//! Status: Phase 1.2 in flight. `canonical` is implemented and tested;
//! `ed25519` (signature verify wrapper) and `chain` (audit anchor
//! Phase 2) are next.

pub mod canonical;
pub mod ed25519;
pub mod hybrid;

pub use canonical::{Canonicalizer, PythonJsonDumpsCanonicalizer};
pub use ed25519::{
    canonical_payload_value, verify_trace, verify_trace_via_directory, PublicKeyDirectory,
};
pub use hybrid::{verify_hybrid, HybridPolicy, VerifyError as HybridVerifyError, VerifyOutcome};

/// Verify-layer errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Signature did not verify against the canonical bytes
    /// (Ed25519 strict-verify path).
    #[error("signature mismatch")]
    SignatureMismatch,

    /// Canonical-bytes encoding produced an output different from
    /// what the agent's signer would have produced. Indicates a bug
    /// in the canonicalizer; never expected at runtime if the parity
    /// test (MISSION.md §4) passes in CI.
    #[error("canonicalization byte-equivalence violated: {0}")]
    Canonicalization(String),

    /// The signing key id wasn't found in the public-key directory
    /// (`accord_public_keys` table; `Backend::lookup_public_key`).
    #[error("unknown signing key id: {0}")]
    UnknownKey(String),

    /// Base64 decoding the signature failed.
    #[error("invalid signature encoding: {0}")]
    InvalidSignature(String),

    /// JSON serialization for canonical bytes failed.
    #[error("internal: {0}")]
    Internal(#[from] serde_json::Error),

    /// v0.3.0 — `trace_schema_version` is in
    /// [`crate::schema::SUPPORTED_VERSIONS`] but the verify dispatch
    /// table doesn't have a canonical-shape arm for it. Should be
    /// impossible at runtime; belt-and-braces typed error so a future
    /// SUPPORTED_VERSIONS expansion that forgets to add the dispatch
    /// arm fails loud instead of silently returning Ok().
    #[error("unsupported schema version for verify dispatch: {0}")]
    UnsupportedSchemaVersion(String),
}

impl Error {
    /// Stable string-token identifying the error variant.
    /// THREAT_MODEL.md AV-15: HTTP / PyO3 sanitization.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::SignatureMismatch => "verify_signature_mismatch",
            Error::Canonicalization(_) => "verify_canonicalization_internal",
            Error::UnknownKey(_) => "verify_unknown_key",
            Error::InvalidSignature(_) => "verify_invalid_signature",
            Error::Internal(_) => "verify_internal",
            Error::UnsupportedSchemaVersion(_) => "verify_unsupported_schema_version",
        }
    }
}
