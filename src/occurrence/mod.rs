//! Occurrence registration + liveness heartbeat substrate (v1.7.3,
//! CIRISPersist#81).
//!
//! # The endpoint-liveness problem
//!
//! CIRISAgent currently *infers* live occurrences by scanning recent
//! task-row activity and dedup'ing `agent_occurrence_id`. That's an
//! inference, not a registration — it can't tell a clean shutdown
//! from a crash and has no TTL.
//!
//! Under the one-key model (PoB §3.2) every occurrence of an agent
//! signs with the *same* Ed25519 identity. So occurrence churn is
//! not membership change — it is *endpoint liveness under a stable
//! identity*. The node layer needs an authoritative, low-latency
//! answer to "which endpoints for identity X are reachable right
//! now."
//!
//! This substrate is that registry. One durable row per live
//! occurrence; `expires_at` is TTL-based so a crashed occurrence
//! ages out without a clean deregister.
//!
//! # Trait surface
//!
//! 4 methods on [`OccurrenceService`]:
//!
//! - **`register_occurrence`** — register (or re-register, idempotent
//!   on `occurrence_id`) an occurrence with a TTL.
//! - **`heartbeat_occurrence`** — bump `last_heartbeat` + `expires_at`
//!   for an already-registered occurrence.
//! - **`deregister_occurrence`** — clean shutdown: remove the row
//!   immediately, don't wait for TTL.
//! - **`list_live_occurrences`** — read-only list of rows whose
//!   `expires_at > now` for one identity.
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `occurrence_invalid_argument`, `occurrence_not_found`,
//!   `occurrence_conflict`, `occurrence_backend`,
//!   `occurrence_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::OccurrenceService;
pub use types::OccurrenceRecord;

/// occurrence-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty `occurrence_id`,
    /// empty `identity`, or `ttl_seconds <= 0`.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found. Reserved for future use; the current trait
    /// surface models the "occurrence not registered" case as a
    /// `false` return on `heartbeat_occurrence` /
    /// `deregister_occurrence`.
    #[error("not found: {0}")]
    NotFound(String),

    /// Constraint conflict (UNIQUE / FK). Reserved for future use —
    /// `register_occurrence` resolves the PK collision via
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
            Error::InvalidArgument(_) => "occurrence_invalid_argument",
            Error::NotFound(_) => "occurrence_not_found",
            Error::Conflict(_) => "occurrence_conflict",
            Error::Backend(_) => "occurrence_backend",
            Error::Internal(_) => "occurrence_internal",
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
            "occurrence_invalid_argument"
        );
        assert_eq!(Error::NotFound("x".into()).kind(), "occurrence_not_found");
        assert_eq!(Error::Conflict("x".into()).kind(), "occurrence_conflict");
        assert_eq!(Error::Backend("x".into()).kind(), "occurrence_backend");
        assert_eq!(Error::Internal("x".into()).kind(), "occurrence_internal");
    }
}
