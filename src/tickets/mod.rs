//! Tickets substrate (v1.5.13, CIRISPersist#59 #5).
//!
//! Fifth of 11 substrate absorptions ending CIRISAgent's direct
//! libsqlite access to `ciris_engine.db`. Absorbs the agent's
//! `tickets` table — work items routed by SOP, status, and
//! assignee. Tickets are typically cross-occurrence (assigned to a
//! specific user / agent across the federation, not occurrence-
//! private state) — hence the `agent_occurrence_id` default is
//! `'__shared__'`, distinct from the `'default'` sentinel other
//! substrates use.
//!
//! The trait exposes 5 methods:
//!
//! - **`upsert_ticket`** — `ticket_id`-keyed UPSERT. Every column
//!   except `created_at` and `submitted_at` is overwritten on
//!   conflict; both creation-time columns stay at their original
//!   values so a retry doesn't clobber when the ticket was created
//!   / submitted.
//!
//! - **`get_ticket`** — point lookup by ticket_id.
//!
//! - **`list_tickets`** — cursor-paged read. Filter by any of
//!   `sop`, `ticket_type`, `status`, `email`, `agent_occurrence_id`,
//!   `automated`, `deadline_before` (for due-deadline scans), and
//!   `last_updated_after` / `last_updated_before` (row-update
//!   windows). Cursor pagination on `(last_updated, ticket_id)`,
//!   newest-first.
//!
//! - **`assign_ticket`** — atomic assignment + status flip. Sets
//!   `user_identifier` to the caller-supplied value, advances
//!   `status` to `assigned` by default (or caller-supplied
//!   `in_progress` etc.), and bumps `last_updated` to NOW.
//!   Idempotent on `(ticket_id, user_identifier)` — re-assigning a
//!   ticket to the same user is a no-op (no row update; we still
//!   return `true` since the row exists in the assigned state).
//!   Returns `false` when the ticket doesn't exist.
//!
//! - **`update_ticket_status`** — focused status update. Bumps
//!   `last_updated`. `completed_at` is caller-supplied — on
//!   terminal-state transitions (`completed`, `cancelled`,
//!   `failed`) the caller passes the timestamp; trait does not
//!   enforce. Optional `notes` is appended via overwrite (caller
//!   reconstructs if append-style semantics are needed). Returns
//!   `false` when the ticket doesn't exist.
//!
//! # Status vocabulary
//!
//! Note: `tickets.status` is LOWERCASE 8-value (`pending |
//! assigned | in_progress | blocked | deferred | completed |
//! cancelled | failed`). Distinct from scheduled_tasks (UPPERCASE
//! 4-value) and partially overlapping with `tasks` (lowercase
//! 6-value). The agent's table declaration is authoritative;
//! persist follows it verbatim. Note the mixed snake_case for
//! `in_progress`.
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `tickets_invalid_argument`, `tickets_not_found`,
//!   `tickets_conflict`, `tickets_backend`, `tickets_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::TicketService;
pub use types::{Ticket, TicketCursor, TicketFilter, TicketListPage, TicketStatus};

/// tickets-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty ticket_id, unknown
    /// status string, out-of-range priority, malformed JSON, out-
    /// of-range limit, etc.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Uniqueness collision or other constraint conflict the trait
    /// surface should not retry. (Idempotent upsert is NOT a
    /// Conflict — this variant covers genuine collisions only.)
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
            Error::InvalidArgument(_) => "tickets_invalid_argument",
            Error::NotFound(_) => "tickets_not_found",
            Error::Conflict(_) => "tickets_conflict",
            Error::Backend(_) => "tickets_backend",
            Error::Internal(_) => "tickets_internal",
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
            "tickets_invalid_argument"
        );
        assert_eq!(Error::NotFound("x".into()).kind(), "tickets_not_found");
        assert_eq!(Error::Conflict("x".into()).kind(), "tickets_conflict");
        assert_eq!(Error::Backend("x".into()).kind(), "tickets_backend");
        assert_eq!(Error::Internal("x".into()).kind(), "tickets_internal");
    }
}
