//! cirislens audit log — hash-chained tamper-evidence (v0.8.1,
//! CIRISPersist#35).
//!
//! Absorbs CIRISAgent's GraphAuditService write path. Per-tenant
//! monotonic `sequence_number` + sha256 `prev_hash` chain. Each
//! entry signs over canonical(entry minus signature); persist
//! verifies on INSERT and refuses chain breaks (AV-49).
//!
//! # Hash-chain shape
//!
//! For a chain `[e₁, e₂, …, eₙ]` under one tenant:
//!
//! - `e₁.prev_hash = [0; 32]` (genesis sentinel)
//! - `e₁.entry_hash = sha256(canonical(e₁ minus signature))`
//! - `eₖ.prev_hash = eₖ₋₁.entry_hash` for k ≥ 2
//! - `eₖ.sequence_number = k` (per-tenant monotonic)
//!
//! Persist's [`AuditService::record_entry`] re-derives `entry_hash`
//! from the canonical bytes, then asserts `prev_hash` matches the
//! preceding entry's `entry_hash` (or zeros for genesis), then
//! asserts the signature verifies against `actor_id` (which IS the
//! Ed25519 pubkey, base64, per the self-signed identity model v0.7.1
//! established for cirisnode envelopes).
//!
//! # Why per-tenant chains
//!
//! Cross-tenant correlation in a single global chain lets one slow
//! signer block the entire federation's audit writes. Per-tenant
//! chains let each principal advance independently while preserving
//! within-tenant tamper-evidence.
//!
//! # Scope per release
//!
//! - **v0.8.1** (this release): V014 migration, wire types,
//!   `AuditService` trait (3 methods), PostgresBackend impl with
//!   transactional INSERT-and-chain-check, hash-chain verify helper,
//!   PyO3 wraps, integration tests covering the chain-break / replay
//!   / cross-tenant rejection paths.

pub mod merkle_leaf;
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub mod merkle_store;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;
pub mod verify;

pub use service::AuditService;
pub use types::{
    AuditEntry, AuditEventRef, AuditEventType, AuditFilter, AuditListPage, ChainVerification,
    ChainVerifyOutcome, CorrelationQuery, CORRELATION_QUERY_MAX_LIMIT,
};

/// audit-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens for HTTP / PyO3
/// sanitization. Verbose `Display` messages stay in tracing only.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty actor_id, malformed
    /// signature, sequence_number out of range, etc.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// AV-49: hash-chain integrity violation. `prev_hash` didn't
    /// match the preceding entry's `entry_hash`, or `entry_hash`
    /// didn't match the re-derived canonical-bytes hash.
    #[error("chain integrity: {0}")]
    ChainIntegrity(String),

    /// Signature verification failed.
    #[error("signature: {0}")]
    Signature(String),

    /// Conflict on `(tenant_id, sequence_number)` UNIQUE — another
    /// writer already claimed this sequence number for the tenant.
    /// Caller should re-read the current sequence and retry.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Row not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Backend-level error (DB connection, JSONB serialization).
    #[error("backend: {0}")]
    Backend(String),

    /// Trait method declared but backend doesn't implement it.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    /// Internal serialization / type-conversion bug.
    #[error("internal: {0}")]
    Internal(String),

    /// Merkle transparency-layer error (v1.5.0 Phase C). Surfaces a
    /// failure from the per-tenant `TransparencyStore<AuditLeaf>`
    /// append / STH sign / STH store path. The audit chain commit
    /// itself is intact (chain commit precedes Merkle hook); callers
    /// observing this variant should NOT re-issue the audit entry —
    /// the chain row already landed. Phase I's backfill recomputes
    /// any missing Merkle projection rows.
    #[error("merkle: {0}")]
    Merkle(String),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "audit_invalid_argument",
            Error::ChainIntegrity(_) => "audit_chain_integrity",
            Error::Signature(_) => "audit_signature",
            Error::Conflict(_) => "audit_conflict",
            Error::NotFound(_) => "audit_not_found",
            Error::Backend(_) => "audit_backend",
            Error::NotImplemented(_) => "audit_not_implemented",
            Error::Internal(_) => "audit_internal",
            Error::Merkle(_) => "audit_merkle",
        }
    }
}

/// Genesis-of-chain sentinel for [`AuditEntry::prev_hash`]. All 32
/// bytes zero. Callers writing the first entry under a new
/// `tenant_id` MUST use this value.
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_tokens_stable() {
        assert_eq!(
            Error::InvalidArgument("x".into()).kind(),
            "audit_invalid_argument"
        );
        assert_eq!(
            Error::ChainIntegrity("x".into()).kind(),
            "audit_chain_integrity"
        );
        assert_eq!(Error::Signature("x".into()).kind(), "audit_signature");
        assert_eq!(Error::Conflict("x".into()).kind(), "audit_conflict");
        assert_eq!(Error::NotFound("x".into()).kind(), "audit_not_found");
        assert_eq!(Error::Backend("x".into()).kind(), "audit_backend");
        assert_eq!(Error::NotImplemented("x").kind(), "audit_not_implemented");
        assert_eq!(Error::Internal("x".into()).kind(), "audit_internal");
        assert_eq!(Error::Merkle("x".into()).kind(), "audit_merkle");
    }

    #[test]
    fn genesis_prev_hash_is_zeros() {
        // AV-49 sentinel locked at v0.8.1 — any change is a threat-
        // model event (chain re-write).
        assert_eq!(GENESIS_PREV_HASH, [0u8; 32]);
    }
}
