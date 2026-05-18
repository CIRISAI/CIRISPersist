//! Agent thoughts substrate (v1.5.10, CIRISPersist#59 #2).
//!
//! Second of 11 substrate absorptions ending CIRISAgent's direct
//! libsqlite access to `ciris_engine.db`. Absorbs the agent's
//! `thoughts` table:
//!
//! - **`upsert_thought`** — thought_id-keyed idempotent upsert. Re-
//!   insert with same payload is a no-op; re-insert with differing
//!   payload overwrites the mutable columns (status, content,
//!   thought_depth, ponder_notes, final_action, …) while preserving
//!   `created_at` and the row's parent + task linkage.
//!
//! - **`get_thought`** — point lookup by id.
//!
//! - **`list_thoughts`** — cursor-paged tenant-style listing with
//!   filter on (occurrence, status, source_task_id, parent_thought_id,
//!   time-window). Hits `thoughts_status_occurrence` in the by-status
//!   happy path and `thoughts_task_recency` for the per-task chain
//!   walk.
//!
//! - **`update_thought_status`** — focused status-only update plus
//!   optional `final_action_json` merge (COALESCE — pass Some(Null)
//!   to overwrite with NULL). Returns false when the thought doesn't
//!   exist (no error — agent treats as "stale id, drop").
//!
//! - **`get_descendants`** — recursive CTE walk from a root thought,
//!   returning the root + every transitive descendant. Ordering:
//!   `thought_depth ASC, thought_id ASC` (depth-first by structure,
//!   tiebroken by id). Both backends use `WITH RECURSIVE` (PG +
//!   SQLite 3.8.3+ — same shape as cirisgraph's k-hop walk).
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `thoughts_invalid_argument`, `thoughts_not_found`,
//!   `thoughts_conflict`, `thoughts_backend`, `thoughts_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::ThoughtService;
pub use types::{
    Thought, ThoughtCursor, ThoughtFilter, ThoughtListPage, ThoughtStatus, ThoughtType,
};

/// thoughts-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty thought_id,
    /// unknown status string, malformed JSON, out-of-range limit, etc.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found (e.g. parent walk rooted at a missing id).
    #[error("not found: {0}")]
    NotFound(String),

    /// Uniqueness or FK conflict that the trait surface should not
    /// retry (e.g. source_task_id reference to a nonexistent task;
    /// parent_thought_id reference to a nonexistent thought).
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
            Error::InvalidArgument(_) => "thoughts_invalid_argument",
            Error::NotFound(_) => "thoughts_not_found",
            Error::Conflict(_) => "thoughts_conflict",
            Error::Backend(_) => "thoughts_backend",
            Error::Internal(_) => "thoughts_internal",
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
            "thoughts_invalid_argument"
        );
        assert_eq!(Error::NotFound("x".into()).kind(), "thoughts_not_found");
        assert_eq!(Error::Conflict("x".into()).kind(), "thoughts_conflict");
        assert_eq!(Error::Backend("x".into()).kind(), "thoughts_backend");
        assert_eq!(Error::Internal("x".into()).kind(), "thoughts_internal");
    }
}
