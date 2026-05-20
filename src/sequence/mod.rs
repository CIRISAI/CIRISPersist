//! Atomic per-identity monotonic sequence substrate (v1.7.1,
//! CIRISPersist#83).
//!
//! # The one-key, many-signers problem
//!
//! A CIRIS 3.0 runtime holds exactly one Ed25519 identity. Every
//! in-process consumer (agent, NodeCore, LensCore) and every
//! occurrence of the agent signs with that one key (PoB §3.2 —
//! one-key model). Anything that emits *ordered* signed output —
//! NodeCore network-message sequence numbers being the canonical
//! case — needs a counter that is atomic across all of those
//! occurrences/consumers. Otherwise two occurrences both emit
//! seq N and the signed stream forks.
//!
//! This substrate is that counter. One durable row per
//! `(identity, stream)` pair; `next_sequence` bumps and returns it
//! in a single atomic statement.
//!
//! # Trait surface
//!
//! 2 methods on [`SequenceService`]:
//!
//! - **`next_sequence`** — atomically bump and return the next
//!   monotonic value. First call for a pair returns 1, then 2, 3,
//!   … Backed by a single `INSERT ... ON CONFLICT DO UPDATE ...
//!   RETURNING` so it is correct under concurrent callers.
//! - **`peek_sequence`** — read the last-issued value WITHOUT
//!   bumping. Returns 0 for a never-issued pair.
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `sequence_invalid_argument`, `sequence_not_found`,
//!   `sequence_conflict`, `sequence_backend`, `sequence_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::SequenceService;

/// sequence-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty `identity`, empty
    /// `stream`.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found. Reserved for future use; the current trait
    /// surface models the "pair never issued" case as `0` on
    /// `peek_sequence`.
    #[error("not found: {0}")]
    NotFound(String),

    /// Constraint conflict (UNIQUE / FK). Reserved for future use
    /// — the issuing UPSERT resolves the PK collision via
    /// `ON CONFLICT DO UPDATE`.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Backend-level error (connection, transaction, lock).
    #[error("backend: {0}")]
    Backend(String),

    /// Internal serialization / type-conversion bug.
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "sequence_invalid_argument",
            Error::NotFound(_) => "sequence_not_found",
            Error::Conflict(_) => "sequence_conflict",
            Error::Backend(_) => "sequence_backend",
            Error::Internal(_) => "sequence_internal",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_tokens_stable() {
        assert_eq!(
            Error::InvalidArgument("x".into()).kind(),
            "sequence_invalid_argument"
        );
        assert_eq!(Error::NotFound("x".into()).kind(), "sequence_not_found");
        assert_eq!(Error::Conflict("x".into()).kind(), "sequence_conflict");
        assert_eq!(Error::Backend("x".into()).kind(), "sequence_backend");
        assert_eq!(Error::Internal("x".into()).kind(), "sequence_internal");
    }
}
