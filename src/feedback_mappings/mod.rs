//! Feedback-mappings substrate (v1.5.18, CIRISPersist#59 #10).
//!
//! Tenth of 11 substrate absorptions ending CIRISAgent's direct
//! libsqlite access to `ciris_engine.db`. Absorbs the agent's
//! `feedback_mappings` table — the link between an inbound feedback
//! Discord-message (or analogous wire-message id) and the agent
//! thought that resolved against it.
//!
//! # Design decision: dedicated substrate vs. folding into cirisgraph_edges
//!
//! The agent's spec called out a design question: "may be foldable
//! into `cirisgraph_edges` if the relationship semantics fit." We
//! ship as a dedicated substrate. Rationale:
//!
//! - `target_thought_id` references `cirislens.thoughts(thought_id)`
//!   — a typed-substrate FK, NOT a graph_nodes FK. cirisgraph_edges
//!   expects `(source_node_id, target_node_id)` both pointing at
//!   graph_nodes; this doesn't fit that shape.
//! - The agent's table semantics ("feedback X applies to thought Y")
//!   are structurally different from "node A relates to node B in
//!   graph G" — feedback rides on Discord-message-to-thought-
//!   resolution pairs, which don't fit cleanly as graph edges.
//! - Folding into cirisgraph_edges would force us to also represent
//!   the thought as a graph_node, doubling the write surface.
//!
//! A dedicated 5-column substrate is the right shape.
//!
//! # Write semantics
//!
//! - **`record_feedback`** — `INSERT ... ON CONFLICT (feedback_id)
//!   DO NOTHING` write-once per feedback id. Returns
//!   [`ClaimResult::Stored`] for the race winner;
//!   [`ClaimResult::AlreadyClaimed`] for the loser (carrying the
//!   existing row).
//! - **`list_feedback_for_thought`** — `SELECT ... WHERE
//!   target_thought_id = $1 ORDER BY created_at DESC LIMIT $2`.
//!   Hits the partial index `feedback_mappings_thought`.
//! - **`list_feedback`** — filter query by feedback_type,
//!   source_message_id, and time window. Ordered DESC by
//!   created_at.
//!
//! # Nullable FK semantics on both backends
//!
//! `target_thought_id` is nullable in the agent's schema. The FK
//! only fires for non-NULL values — both PG and SQLite handle this
//! natively (NULL FKs pass the constraint check without lookup). A
//! feedback row CAN be recorded before any thought has resolved
//! against it; the lookup just returns no descendants.
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `feedback_mappings_invalid_argument`,
//!   `feedback_mappings_not_found`,
//!   `feedback_mappings_conflict`,
//!   `feedback_mappings_backend`,
//!   `feedback_mappings_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::FeedbackMappingService;
pub use types::{FeedbackFilter, FeedbackMapping};

/// feedback_mappings-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty `feedback_id`,
    /// out-of-range limit, etc.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found. Currently unused by the trait surface —
    /// `list_*` methods model the empty case as an empty `Vec`.
    /// Reserved for future point-lookup variants.
    #[error("not found: {0}")]
    NotFound(String),

    /// Constraint conflict (FK violation against `cirislens.thoughts`
    /// when `target_thought_id` is non-NULL). Race-loser on
    /// `record_feedback` is NOT a `Conflict` — it's
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
            Error::InvalidArgument(_) => "feedback_mappings_invalid_argument",
            Error::NotFound(_) => "feedback_mappings_not_found",
            Error::Conflict(_) => "feedback_mappings_conflict",
            Error::Backend(_) => "feedback_mappings_backend",
            Error::Internal(_) => "feedback_mappings_internal",
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
            "feedback_mappings_invalid_argument"
        );
        assert_eq!(
            Error::NotFound("x".into()).kind(),
            "feedback_mappings_not_found"
        );
        assert_eq!(
            Error::Conflict("x".into()).kind(),
            "feedback_mappings_conflict"
        );
        assert_eq!(
            Error::Backend(String::new()).kind(),
            "feedback_mappings_backend"
        );
        assert_eq!(
            Error::Internal(String::new()).kind(),
            "feedback_mappings_internal"
        );
    }
}
