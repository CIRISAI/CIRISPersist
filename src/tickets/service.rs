//! `TicketService` trait surface (v1.5.13, CIRISPersist#59 #5).
//!
//! 5 methods. Same `impl Future<...> + Send` GAT pattern as the
//! rest of the v0.8.x / v1.x substrate traits.

use std::future::Future;

use chrono::{DateTime, Utc};

use super::types::{Ticket, TicketCursor, TicketFilter, TicketListPage, TicketStatus};
use super::Error;

/// Tickets substrate trait — absorbs CIRISAgent's `tickets` table.
pub trait TicketService: Send + Sync {
    /// Upsert a ticket. INSERT on first call, UPDATE on conflict by
    /// `ticket_id`. Every column except `created_at` and
    /// `submitted_at` is overwritten on conflict; both creation-
    /// time columns stay at their original values so a retry
    /// doesn't clobber when the ticket was created / submitted.
    fn upsert_ticket(&self, ticket: Ticket) -> impl Future<Output = Result<(), Error>> + Send;

    /// Point lookup. Returns `None` when no matching row.
    fn get_ticket(
        &self,
        ticket_id: &str,
    ) -> impl Future<Output = Result<Option<Ticket>, Error>> + Send;

    /// Cursor-paged listing. Newest-first by `last_updated`. Filter
    /// by any combination of `sop`, `ticket_type`, `status`,
    /// `email`, `agent_occurrence_id`, `automated`,
    /// `deadline_before` (for due-deadline scans), and
    /// `last_updated_after` / `last_updated_before` (row-update
    /// windows). Cursor pagination on `(last_updated, ticket_id)`.
    fn list_tickets(
        &self,
        filter: TicketFilter,
        cursor: Option<TicketCursor>,
        limit: i64,
    ) -> impl Future<Output = Result<TicketListPage, Error>> + Send;

    /// Atomic assignment + status flip. Sets `user_identifier` to
    /// the supplied value, advances `status` (default `assigned`,
    /// or caller-supplied — typically `in_progress`), and bumps
    /// `last_updated` to NOW. Idempotent on `(ticket_id,
    /// user_identifier)` — re-assigning to the same user is a no-op
    /// (returns `true`; the row is in the assigned state).
    /// Returns `false` when the ticket doesn't exist.
    fn assign_ticket(
        &self,
        ticket_id: &str,
        user_identifier: &str,
        new_status: Option<TicketStatus>,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// Focused status update. Bumps `last_updated` to NOW.
    /// `completed_at` is caller-supplied — on terminal-state
    /// transitions (`completed` / `cancelled` / `failed`) the
    /// caller passes the timestamp; the trait does not enforce that
    /// the timestamp is set or that the status is terminal.
    /// `notes` overwrites the existing value when `Some(_)` is
    /// passed; `None` preserves the existing value.
    ///
    /// Returns `false` when the ticket doesn't exist (no error —
    /// callers treat as "stale id, drop").
    fn update_ticket_status(
        &self,
        ticket_id: &str,
        new_status: TicketStatus,
        completed_at: Option<DateTime<Utc>>,
        notes: Option<String>,
    ) -> impl Future<Output = Result<bool, Error>> + Send;
}
