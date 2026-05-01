//! Signature verification + canonical bytes (TRACE_WIRE_FORMAT.md §8).
//!
//! Mission alignment (MISSION.md §2 — `verify/`): signature
//! verification is the cryptographic floor of the Coherent
//! Intersection Hypothesis. Every persisted row must have been
//! provably produced by the claimed agent at the claimed moment, OR
//! be explicitly marked unverified. There is no third state.
//!
//! Status: Phase 1.2 — module skeleton; impl lands next via TDD per
//! task #10 in the project task list.

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
}
