//! Wise-Authority cert substrate (v1.5.19, CIRISPersist#59 #11, FINAL).
//!
//! ELEVENTH and FINAL substrate absorption ending CIRISAgent's direct
//! libsqlite access to `ciris_engine.db`. Absorbs the agent's
//! `wa_cert` table — the Wise-Authority cert directory keyed on
//! `wa_id`. Per the "persist is the only library that opens the file"
//! guarantee these WA certs live in the engine DB (NOT a separate
//! `auth.db`).
//!
//! # 24 columns, 7 trait methods
//!
//! - `upsert_wa_cert` — idempotent upsert on `wa_id`. Mutable columns
//!   (`last_login`, `active`, `scopes`, etc.) overwrite on conflict;
//!   `created` is preserved.
//! - `get_wa_cert(wa_id)` — point lookup by PK.
//! - `get_by_kid(jwt_kid)` — JWT verification hot path; hits the
//!   unique `wa_cert_jwt_kid` index.
//! - `get_by_oauth(provider, external_id)` — OAuth login path; hits
//!   the partial `wa_cert_oauth` index.
//! - `list_by_role(role, limit)` — list_observers / list_authorities;
//!   filters by role + `active = TRUE`, hits the partial
//!   `wa_cert_role_active` index.
//! - `set_active(wa_id, active)` — activity toggle. Returns `true` if
//!   any row was updated; `false` if `wa_id` doesn't exist.
//! - `update_last_login(wa_id, login_time)` — last-login bookkeeping.
//!   Returns `true` if any row was updated; `false` if `wa_id` doesn't
//!   exist.
//!
//! # Self-FK semantics
//!
//! `parent_wa_id` references `wa_cert(wa_id)`. On PG the FK is
//! `DEFERRABLE INITIALLY DEFERRED` so a one-tx ceremony writing a
//! parent + child WA pair in either order is supported. On SQLite the
//! FK is immediate (`PRAGMA foreign_keys=ON` set by the store layer)
//! — the parent must already exist when the child INSERT runs, OR the
//! child must be inserted with `parent_wa_id = NULL`.
//!
//! Both backends pass nullable FKs natively — `parent_wa_id = NULL`
//! bypasses the constraint check.
//!
//! # Token-type vocabulary
//!
//! Inferred from the agent's TokenType enum: `standard | session |
//! api_key | oauth | service`. Caller-validated either way (cert mint
//! happens in CIRISAgent), but a DB-level CHECK keeps the schema
//! truthful about which strings persist would round-trip.
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `wa_cert_invalid_argument`, `wa_cert_not_found`,
//!   `wa_cert_conflict`, `wa_cert_backend`, `wa_cert_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::WaCertService;
pub use types::{TokenType, WaCert, WaRole};

/// wa_cert-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty `wa_id`, empty
    /// `jwt_kid`, out-of-range limit, etc.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found. Returned by `set_active` / `update_last_login`
    /// for missing rows ONLY via the trait's `bool` return; reserved
    /// here for future point-lookup variants that surface absence as
    /// an error.
    #[error("not found: {0}")]
    NotFound(String),

    /// Constraint conflict — UNIQUE violation on `jwt_kid` when two
    /// different `wa_id`s try to claim the same kid, or FK violation
    /// on `parent_wa_id` when the referenced parent WA doesn't exist.
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
            Error::InvalidArgument(_) => "wa_cert_invalid_argument",
            Error::NotFound(_) => "wa_cert_not_found",
            Error::Conflict(_) => "wa_cert_conflict",
            Error::Backend(_) => "wa_cert_backend",
            Error::Internal(_) => "wa_cert_internal",
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
            "wa_cert_invalid_argument"
        );
        assert_eq!(Error::NotFound("x".into()).kind(), "wa_cert_not_found");
        assert_eq!(Error::Conflict("x".into()).kind(), "wa_cert_conflict");
        assert_eq!(Error::Backend(String::new()).kind(), "wa_cert_backend");
        assert_eq!(Error::Internal(String::new()).kind(), "wa_cert_internal");
    }
}
