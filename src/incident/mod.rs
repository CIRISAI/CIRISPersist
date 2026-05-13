//! Incident records (v0.8.3, CIRISPersist#37).
//!
//! Absorbs CIRISAgent's `IncidentManagementService`. Two distinctive
//! behaviors over the generic-row write pattern used elsewhere in
//! v0.8.x:
//!
//! 1. **Correlation-keyed dedup on record** — when a new incident's
//!    `correlation_keys` overlap any existing OPEN incident's
//!    keys for the same `(tenant_id, category)`, the trait bumps
//!    `occurrences` + refreshes `last_seen_at` on the existing row
//!    instead of inserting a new one. Avoids alert-storm proliferation
//!    when the underlying failure mode emits repeatedly before
//!    operator response.
//!
//! 2. **State machine** (AV-55) — `open → investigating → resolved →
//!    closed`. No backflow; persist refuses regressive transitions.
//!    Each state transition is recorded in the `state` column with
//!    `resolved_at` + `resolution_notes` populated when crossing
//!    the resolved or closed boundary.
//!
//! # Threat-model anchors (THREAT_MODEL.md §4)
//!
//! - **AV-55** — state-machine guard: regressive transitions
//!   (`closed → open`, etc.) reject as `Error::InvalidTransition`.
//! - **AV-56** — correlation_keys bound: max 32 keys per incident,
//!   max 256 bytes per key. Enforced at the trait surface BEFORE
//!   binding to SQL.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
pub mod types;

pub use service::IncidentService;
pub use types::{
    Incident, IncidentFilter, IncidentListPage, IncidentRef, IncidentState, IncidentTransition,
};

/// incident-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — AV-56 correlation_keys
    /// bound exceeded, empty title, unknown severity, etc.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// AV-55: state machine refused the transition.
    #[error("invalid transition: {0}")]
    InvalidTransition(String),

    /// Row not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Backend-level error.
    #[error("backend: {0}")]
    Backend(String),

    /// Trait method declared but backend doesn't implement it.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    /// Internal serialization / type-conversion bug.
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "incident_invalid_argument",
            Error::InvalidTransition(_) => "incident_invalid_transition",
            Error::NotFound(_) => "incident_not_found",
            Error::Backend(_) => "incident_backend",
            Error::NotImplemented(_) => "incident_not_implemented",
            Error::Internal(_) => "incident_internal",
        }
    }
}

/// AV-56: max correlation keys per incident.
pub const MAX_CORRELATION_KEYS: usize = 32;

/// AV-56: max bytes per individual correlation key.
pub const MAX_CORRELATION_KEY_BYTES: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_tokens_stable() {
        assert_eq!(
            Error::InvalidArgument("x".into()).kind(),
            "incident_invalid_argument"
        );
        assert_eq!(
            Error::InvalidTransition("x".into()).kind(),
            "incident_invalid_transition"
        );
        assert_eq!(Error::NotFound("x".into()).kind(), "incident_not_found");
        assert_eq!(Error::Backend("x".into()).kind(), "incident_backend");
        assert_eq!(
            Error::NotImplemented("x").kind(),
            "incident_not_implemented"
        );
        assert_eq!(Error::Internal("x".into()).kind(), "incident_internal");
    }

    #[test]
    fn av_56_correlation_bounds_locked() {
        // Any change to either of these is a threat-model event
        // (revisit AV-56 entry first).
        assert_eq!(MAX_CORRELATION_KEYS, 32);
        assert_eq!(MAX_CORRELATION_KEY_BYTES, 256);
    }
}
