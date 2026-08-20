//! The `registry_key_escrows` consumer-table family (CIRISPersist#752).
//!
//! The CIRISRegistry → CIRISServer fold's one storage ask, decided on #751:
//! registry's `key_escrows` working index (`rust-registry/db/escrows.rs`,
//! served by the three PortalService RPCs `RequestKeyEscrow` /
//! `RequestKeyRecovery` / `ListKeyEscrows`), folded onto persist's
//! consumer-table pattern — the `cirislens_wa_cert` precedent.
//!
//! # The constitutional boundary (why this is a table and must stay one)
//!
//! CC 4.4.3.2.8 defines key escrow as **`archive_custody`**: an
//! institutional custodian/escrow role holding per-epoch keys decoupled
//! from the live roster, **steward-bound**, authorized by `delegates_to`
//! (CC 2.4.1.2) and operating by emitting `key_grant`s (CC 3.3.2) — "rides
//! the key-grant/escrow cascade." Both legs already exist on persist's
//! planes (`key_grant`'s `(scope_kind, scope_id, epoch)` generalization
//! shipped in v34.0.0, CIRISPersist#704). And CC 1.7's 1+4 lockdown — "no
//! new attestation_type and no new envelope field" — closes the "escrow
//! envelope kind" branch permanently: custody claims that want federation
//! visibility COMPOSE from existing primitives. This table is the
//! custodian's **working index** (who escrows what, expiry, status) and
//! never key material, never a shadow claims plane.
//!
//! The prior-art shape is Keybase's server-side device/paper-key index:
//! authoritative custody STATE lives in an ordinary database while the
//! authorization chain lives in the signed sigchain — the index answers
//! "what does the custodian hold", the chain answers "who may".
//!
//! # 1 table, 5 trait methods
//!
//! - `create_escrow` — idempotent for byte-identical re-puts on
//!   `escrow_id`; a differing row on an occupied id is `Conflict` (the
//!   #719 absorb-then-re-read discipline).
//! - `get_escrow` / `list_escrows_for_org` / `list_escrows_for_key` —
//!   point and index reads (registry's `ListKeyEscrows` surface).
//! - `set_escrow_status` — the lifecycle door: `active` may move to
//!   `recovered` / `revoked` / `expired`; terminal states are IMMUTABLE
//!   (a custody outcome pins, it never flips); same-state re-assertion is
//!   an idempotent no-op.
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens: `key_escrows_invalid_argument`,
//!   `key_escrows_not_found`, `key_escrows_conflict`,
//!   `key_escrows_backend`, `key_escrows_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::KeyEscrowService;
pub use types::{EscrowStatus, EscrowType, KeyEscrowRow};

/// key_escrows-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty ids, unknown vocabulary.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found — transitioning or reading an escrow that was never
    /// created.
    #[error("not found: {0}")]
    NotFound(String),

    /// The fail-secure refusals: a differing row on an occupied
    /// `escrow_id`, or a status transition out of a terminal state.
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
            Error::InvalidArgument(_) => "key_escrows_invalid_argument",
            Error::NotFound(_) => "key_escrows_not_found",
            Error::Conflict(_) => "key_escrows_conflict",
            Error::Backend(_) => "key_escrows_backend",
            Error::Internal(_) => "key_escrows_internal",
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
            "key_escrows_invalid_argument"
        );
        assert_eq!(Error::NotFound("x".into()).kind(), "key_escrows_not_found");
        assert_eq!(Error::Conflict("x".into()).kind(), "key_escrows_conflict");
        assert_eq!(Error::Backend(String::new()).kind(), "key_escrows_backend");
        assert_eq!(
            Error::Internal(String::new()).kind(),
            "key_escrows_internal"
        );
    }
}
