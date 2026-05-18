//! Continuity-awareness substrate (v1.5.17, CIRISPersist#59 #9).
//!
//! Ninth of 11 substrate absorptions ending CIRISAgent's direct
//! libsqlite access to `ciris_engine.db`. Absorbs the agent's
//! `continuity_awareness` table — the per-shutdown record an agent
//! leaves behind so the next boot can surface "where did I leave
//! off" continuity context.
//!
//! # Cross-substrate FK (a first for the absorption set)
//!
//! Every previous substrate in the absorption queue either had no
//! FKs or referenced sibling cirislens tables (tasks ←→ thoughts
//! ←→ deferral_reports). This one references the v0.8.0 cirisgraph
//! substrate's `cirisgraph.nodes` / SQLite `cirisgraph_nodes`
//! table via the composite PK `(node_id, scope)`:
//!
//!   FOREIGN KEY (preservation_node_id, preservation_scope)
//!       REFERENCES cirisgraph.nodes (node_id, scope)
//!       DEFERRABLE INITIALLY DEFERRED       -- PG only
//!
//! The cargo feature [`cirislens_continuity_awareness`] declares
//! a transitive dependency on the [`cirisgraph`] feature so the
//! migrations are required to have run in the right order.
//!
//! # Write semantics
//!
//! - **`record_shutdown`** — `INSERT ... ON CONFLICT (id) DO
//!   NOTHING` write-once per shutdown id. Returns
//!   [`ClaimResult::Stored`] for the race winner;
//!   [`ClaimResult::AlreadyClaimed`] for the loser (carrying the
//!   existing row).
//! - **`get_latest_shutdown`** — `SELECT ... WHERE agent_id = $1
//!   ORDER BY shutdown_timestamp DESC LIMIT 1`. Used on next boot
//!   to surface "where did I leave off."
//! - **`record_reactivation`** — `UPDATE ... SET reactivation_count
//!   = reactivation_count + 1` on the most-recent non-terminal
//!   shutdown row for the agent. Returns `true` when a row was
//!   updated; `false` when the agent has only terminal shutdowns
//!   or no shutdowns at all.
//!
//! # Schema parity with the agent
//!
//! 14 columns matching CIRISAgent v2.8.13 verbatim. PG promotes
//! the agent's TEXT JSON columns (`unfinished_tasks`,
//! `deferred_goals`) to JSONB for richer query semantics; the
//! Rust struct rides `Option<serde_json::Value>` on both backends
//! so the wire shape is symmetric.
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `continuity_awareness_invalid_argument`,
//!   `continuity_awareness_not_found`,
//!   `continuity_awareness_conflict`,
//!   `continuity_awareness_backend`,
//!   `continuity_awareness_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::ContinuityAwarenessService;
pub use types::ContinuityAwareness;

/// continuity_awareness-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty `id` / `agent_id` /
    /// required text columns, unknown scope vocabulary.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found. Currently unused by the trait surface —
    /// `get_latest_shutdown` models the empty case as
    /// `Option::None` and `record_reactivation` as `bool` false.
    /// Reserved for future variants.
    #[error("not found: {0}")]
    NotFound(String),

    /// Constraint conflict (e.g. CHECK on `preservation_scope` /
    /// `reactivation_count`, FK violation against `cirisgraph.nodes`)
    /// that the trait surface should not retry. Race-loser on
    /// `record_shutdown` is NOT a `Conflict` — it's
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
            Error::InvalidArgument(_) => "continuity_awareness_invalid_argument",
            Error::NotFound(_) => "continuity_awareness_not_found",
            Error::Conflict(_) => "continuity_awareness_conflict",
            Error::Backend(_) => "continuity_awareness_backend",
            Error::Internal(_) => "continuity_awareness_internal",
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
            "continuity_awareness_invalid_argument"
        );
        assert_eq!(
            Error::NotFound("x".into()).kind(),
            "continuity_awareness_not_found"
        );
        assert_eq!(
            Error::Conflict("x".into()).kind(),
            "continuity_awareness_conflict"
        );
        assert_eq!(
            Error::Backend("x".into()).kind(),
            "continuity_awareness_backend"
        );
        assert_eq!(
            Error::Internal("x".into()).kind(),
            "continuity_awareness_internal"
        );
    }
}
