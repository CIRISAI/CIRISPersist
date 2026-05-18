//! Creation-ceremonies substrate (v1.5.16, CIRISPersist#59 #8).
//!
//! Eighth of 11 substrate absorptions ending CIRISAgent's direct
//! libsqlite access to `ciris_engine.db`. Absorbs the agent's
//! `creation_ceremonies` table — identity-creation history (when
//! did agent X create agent Y, who was the human witness, which
//! WA signed off, what's the ethical justification, etc.).
//!
//! # Write semantics
//!
//! Write-once-mostly. Ceremonies are recorded once via
//! [`CreationCeremonyService::record_ceremony`] using
//! `INSERT ... ON CONFLICT DO NOTHING` so a race-loser doesn't
//! overwrite the existing row; the loser reads back the original
//! and gets it via [`crate::ClaimResult::AlreadyClaimed`].
//!
//! The status column does transition across the lifecycle —
//! `pending` → `in_progress` → `completed`/`failed`/`revoked` — so
//! we ship a focused [`CreationCeremonyService::update_ceremony_status`]
//! method that bypasses the full UPSERT path for status-only
//! advancement.
//!
//! # Schema parity with the agent
//!
//! 14 columns, all matching CIRISAgent v2.8.13 verbatim. No FKs
//! (the various `*_agent_id` references are free-form federation-
//! wide pointers; they cross substrate boundaries and aren't
//! constrained at the table layer). `expected_capabilities` is
//! preserved as TEXT (not JSONB) because the agent stores it as a
//! TEXT-encoded JSON array — keeping the wire shape literal across
//! the absorb boundary lets callers ride the same payload.
//!
//! # Trait surface
//!
//! 4 methods on [`CreationCeremonyService`]:
//!
//! - **`record_ceremony`** — write-once via INSERT ... ON CONFLICT
//!   DO NOTHING. Returns a [`crate::ClaimResult`] so race-losers
//!   get the EXISTING row, never overwrite it.
//! - **`get_ceremony`** — point lookup by ceremony_id.
//! - **`list_ceremonies`** — history query, filterable on
//!   creator/WA/new_agent/status/time window. Ordered by timestamp
//!   DESC, limited.
//! - **`update_ceremony_status`** — atomic state advance. Returns
//!   `false` when the row doesn't exist.
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `creation_ceremonies_invalid_argument`,
//!   `creation_ceremonies_not_found`,
//!   `creation_ceremonies_conflict`,
//!   `creation_ceremonies_backend`,
//!   `creation_ceremonies_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::CreationCeremonyService;
pub use types::{CeremonyFilter, CeremonyStatus, CreationCeremony};

/// creation_ceremonies-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty `ceremony_id` /
    /// `creator_agent_id` / required text columns, out-of-range
    /// limit, unknown status string.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found (currently unused by the trait surface — both
    /// `get_ceremony` and `update_ceremony_status` model the
    /// "row doesn't exist" case as `Option::None` / `bool` false
    /// respectively. Reserved for future variants).
    #[error("not found: {0}")]
    NotFound(String),

    /// Constraint conflict (e.g. CHECK on `ceremony_status`) that
    /// the trait surface should not retry. Race-loser on
    /// `record_ceremony` is NOT a `Conflict` — it's
    /// `ClaimResult::AlreadyClaimed` carrying the existing row.
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
            Error::InvalidArgument(_) => "creation_ceremonies_invalid_argument",
            Error::NotFound(_) => "creation_ceremonies_not_found",
            Error::Conflict(_) => "creation_ceremonies_conflict",
            Error::Backend(_) => "creation_ceremonies_backend",
            Error::Internal(_) => "creation_ceremonies_internal",
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
            "creation_ceremonies_invalid_argument"
        );
        assert_eq!(
            Error::NotFound("x".into()).kind(),
            "creation_ceremonies_not_found"
        );
        assert_eq!(
            Error::Conflict("x".into()).kind(),
            "creation_ceremonies_conflict"
        );
        assert_eq!(
            Error::Backend("x".into()).kind(),
            "creation_ceremonies_backend"
        );
        assert_eq!(
            Error::Internal("x".into()).kind(),
            "creation_ceremonies_internal"
        );
    }
}
