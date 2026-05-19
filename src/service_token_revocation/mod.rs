//! Service-token revocation substrate (v1.5.23, CIRISPersist#64).
//!
//! Absorbs CIRISAgent's standalone `revoked_service_tokens.db`
//! aiosqlite file — the last direct `aiosqlite` consumer in the
//! agent. With this substrate landed, `aiosqlite` drops out of
//! CIRISAgent's `requirements.txt` (CIRISAgent 2.9.0 Phase 2b
//! dependency-removal blocker).
//!
//! # The revocation model
//!
//! Write-once, read-many. The agent's `auth_service` hashes a
//! service token at revocation time (SHA-256 digest) and records
//! one row keyed on `token_hash`. The agent then caches the full
//! table in memory at boot (a `set` of revoked hashes) and
//! point-checks each inbound token against the cache. Persist
//! mirrors that shape: a 4-column table with `token_hash` as PK.
//!
//! NOT a `wa_id` — service tokens are mint-and-revoke credentials
//! that don't round-trip a WA cert. The two tables (`wa_cert` from
//! V034 + `revoked_service_tokens` from V037) coexist with no FK
//! between them; see CIRISPersist#64 for the distinction.
//!
//! # Trait surface
//!
//! 3 methods on [`ServiceTokenRevocationService`]:
//!
//! - **`record_revocation`** — idempotent upsert keyed on
//!   `token_hash` (`ON CONFLICT DO NOTHING`). The first record
//!   wins; subsequent records with the same hash are silently
//!   ignored so callers can retry safely.
//! - **`list_revocations`** — full table dump for the agent's
//!   boot-time cache load. Returns empty `Vec` on cold tables
//!   (not an error).
//! - **`check_revocation`** — point-lookup by PK. Returns the row
//!   when present, `None` otherwise.
//!
//! No filter / cursor / list-page shapes: the table is small (a
//! deployment's revocation history) and the agent loads it all at
//! startup.
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `service_token_revocation_invalid_argument`,
//!   `service_token_revocation_not_found`,
//!   `service_token_revocation_conflict`,
//!   `service_token_revocation_backend`,
//!   `service_token_revocation_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::ServiceTokenRevocationService;
pub use types::RevokedServiceToken;

/// service_token_revocation-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty `token_hash`,
    /// empty `revoked_by`, empty `reason`.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found. Reserved for future use; the current trait
    /// surface models the "row doesn't exist" case as
    /// `Option::None` on `check_revocation`.
    #[error("not found: {0}")]
    NotFound(String),

    /// Constraint conflict (UNIQUE / FK). Reserved for future use
    /// — today the substrate has no FKs and the only UNIQUE is
    /// the PK, which `record_revocation` handles via
    /// `ON CONFLICT DO NOTHING`.
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
            Error::InvalidArgument(_) => "service_token_revocation_invalid_argument",
            Error::NotFound(_) => "service_token_revocation_not_found",
            Error::Conflict(_) => "service_token_revocation_conflict",
            Error::Backend(_) => "service_token_revocation_backend",
            Error::Internal(_) => "service_token_revocation_internal",
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
            "service_token_revocation_invalid_argument"
        );
        assert_eq!(
            Error::NotFound("x".into()).kind(),
            "service_token_revocation_not_found"
        );
        assert_eq!(
            Error::Conflict("x".into()).kind(),
            "service_token_revocation_conflict"
        );
        assert_eq!(
            Error::Backend("x".into()).kind(),
            "service_token_revocation_backend"
        );
        assert_eq!(
            Error::Internal("x".into()).kind(),
            "service_token_revocation_internal"
        );
    }
}
