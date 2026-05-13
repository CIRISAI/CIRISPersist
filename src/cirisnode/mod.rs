//! CIRISNodeCore federation-consensus substrate (v0.7.0+).
//!
//! Implementation of [`FSD/CIRIS_PERSIST.md`](../../../FSD/CIRIS_PERSIST.md)
//! Appendix A. Persist hosts the federation-consensus row classes
//! (Contribution / Vote / Ledger / Moderation / Slashing /
//! Reconsideration) that `CIRISNodeCore` produces. This is a
//! **distinct track** from the v0.6.x lens/agent/bridge substrate
//! — different consumer ecosystem, different Cargo feature
//! (`cirisnode`), different PostgreSQL schema (`cirisnode.*` vs
//! `cirislens.*` / `cirislens_secrets.*`).
//!
//! # Why a separate substrate
//!
//! Per FSD Appendix A.1, the federation-consensus row classes are
//! structurally distinct from the agent-local runtime state that
//! Phase 3 of the main FSD subsumes (`tasks`, `thoughts`,
//! `agent_deferrals_*`, etc.). The agent-local tables hold one
//! agent's runtime state; the federation-consensus tables hold the
//! federation's consensus output across N agents + N witnesses.
//! Same persist crate, different write paths, different audit
//! semantics.
//!
//! # Surface (FSD Appendix A.2 + A.3)
//!
//! - **8 typed-write methods** on the [`NodeCoreService`] trait
//!   (v0.7.0-α3): `put_contribution`, `cast_vote`,
//!   `update_credits_ledger`, `update_expertise_ledger`,
//!   `put_moderation_event`, `put_slashing_attestation`,
//!   `put_reconsideration_request`, `put_reconsideration_attestation`.
//! - **5 read-surface clusters** (v0.7.0-α3): routing-eligibility,
//!   vote-weighting, bulk-list (newest-first cursor pagination,
//!   matching the v0.5.5 §I shape), pending-vs-canonical split,
//!   ledger point-lookups.
//!
//! # Audit envelope discipline
//!
//! Every row carries the standard CIRISPersist audit columns
//! (`signature`, `signing_key_id`, `signature_verified`,
//! `original_content_hash`, `scrub_signature_classical`,
//! `scrub_signature_pqc`, `scrub_key_id`, `scrub_timestamp`,
//! `pqc_completed_at`, `persist_row_hash`). The ingest path
//! verifies the hybrid Ed25519 + ML-DSA-65 signature before INSERT
//! (matches federation_directory discipline from V004).
//!
//! # Scope per release
//!
//! - **v0.7.0-α1** (this commit): Cargo feature + V011 migration
//!   + module skeleton + [`Error`] type with stable `kind()` tokens.
//! - **v0.7.0-α2**: wire types (`ContributionEnvelope`,
//!   `VoteEnvelope`, payload variants per `CIRISNodeCore/SCHEMA.md`
//!   §3–§10).
//! - **v0.7.0-α3**: `NodeCoreService` trait surface (8 writes + 5
//!   reads, `impl Future + Send` GAT pattern).
//! - **v0.7.0-α4**: `PostgresBackend` impl.
//! - **v0.7.0-α5**: Engine PyO3 wraps.
//! - **v0.7.0**: release tag.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
pub mod types;

pub use service::NodeCoreService;
pub use types::{
    Cell, ContributionEnvelope, ContributionListPage, ContributionType, ContributionsFilter,
    CreditsLedgerEntry, CreditsUpdate, DiversityProof, ExpertiseLedgerEntry, ExpertiseUpdate,
    HybridSignature, ListCursor, ModerationEvent, ReconsiderationAttestation,
    ReconsiderationRequest, RoutableContributor, SlashingAttestation, VoteEnvelope, VoteListPage,
    VoteWeight, VotesFilter, Witness, WitnessSet,
};

/// Federation-consensus-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens for HTTP / PyO3
/// sanitization. Verbose `Display` messages stay in tracing only.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments (malformed envelope,
    /// unknown contribution_type, missing required field, etc.).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Authorization layer rejected the operation (e.g. cast_vote
    /// from a voter whose Expertise ledger entry is below the
    /// minimum required by the cell's voting policy).
    #[error("not authorized: {0}")]
    NotAuthorized(String),

    /// Signature verification failed on a typed-write envelope.
    /// Persist refuses to insert; caller must re-sign and retry.
    #[error("signature: {0}")]
    Signature(String),

    /// Conflict on a uniqueness constraint — duplicate
    /// contribution_id, voter casting twice on the same subject,
    /// etc. Caller decides whether to surface as a 409 or no-op.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Row not found (read-side path) — recall, ledger point-lookup,
    /// etc. Distinct from `NotAuthorized` (which implies the row
    /// EXISTS but caller can't access it).
    #[error("not found: {0}")]
    NotFound(String),

    /// Backend-level error (DB connection, JSONB serialization).
    /// String-typed because each backend has its own error tree.
    #[error("backend: {0}")]
    Backend(String),

    /// Surface declared on the trait but the backend doesn't
    /// implement it. Memory backend returns this for the typed
    /// write paths; sqlite backend (when added) likewise.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    /// Internal serialization / type-conversion bug. Indicates a
    /// persist bug; operators should file an issue.
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    /// Mirrors the kind() convention from `crate::secrets::SecretsError`
    /// / `crate::read::Error` / `crate::pipeline::Error`.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "cirisnode_invalid_argument",
            Error::NotAuthorized(_) => "cirisnode_not_authorized",
            Error::Signature(_) => "cirisnode_signature",
            Error::Conflict(_) => "cirisnode_conflict",
            Error::NotFound(_) => "cirisnode_not_found",
            Error::Backend(_) => "cirisnode_backend",
            Error::NotImplemented(_) => "cirisnode_not_implemented",
            Error::Internal(_) => "cirisnode_internal",
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
            "cirisnode_invalid_argument"
        );
        assert_eq!(
            Error::NotAuthorized("x".into()).kind(),
            "cirisnode_not_authorized"
        );
        assert_eq!(Error::Signature("x".into()).kind(), "cirisnode_signature");
        assert_eq!(Error::Conflict("x".into()).kind(), "cirisnode_conflict");
        assert_eq!(Error::NotFound("x".into()).kind(), "cirisnode_not_found");
        assert_eq!(Error::Backend("x".into()).kind(), "cirisnode_backend");
        assert_eq!(
            Error::NotImplemented("x").kind(),
            "cirisnode_not_implemented"
        );
        assert_eq!(Error::Internal("x".into()).kind(), "cirisnode_internal");
    }
}
