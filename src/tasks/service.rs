//! `TaskService` trait surface (v1.5.9, CIRISPersist#59 #1).
//!
//! 6 methods. Same `impl Future<...> + Send` GAT pattern as the
//! rest of v0.8.x / v1.x substrate traits.

use std::future::Future;

use crate::ClaimResult;

use super::types::{Task, TaskCursor, TaskFilter, TaskListPage, TaskStatus};
use super::Error;

/// Agent tasks substrate trait — absorbs CIRISAgent's `tasks`
/// table write + read + state-update + atomic-claim surface.
pub trait TaskService: Send + Sync {
    /// Idempotent upsert keyed on `task_id`. Re-insert with the same
    /// data is a no-op; re-insert with differing data overwrites
    /// mutable columns (description, channel_id, status, priority,
    /// context, outcome, retry_count, signature triple,
    /// updated_info_*, images) while preserving `created_at` from the
    /// original row.
    fn upsert_task(&self, task: Task) -> impl Future<Output = Result<(), Error>> + Send;

    /// Read one task by id. Returns `None` if no matching row.
    fn get_task(&self, task_id: &str) -> impl Future<Output = Result<Option<Task>, Error>> + Send;

    /// Cursor-paged listing. Newest-first by `updated_at`. The
    /// `(agent_occurrence_id, status, updated_at DESC)` composite
    /// index serves the happy path when both filter fields are set;
    /// other filter shapes fall back to a `channel` or full-table
    /// scan as appropriate.
    fn list_tasks(
        &self,
        filter: TaskFilter,
        cursor: Option<TaskCursor>,
        limit: i64,
    ) -> impl Future<Output = Result<TaskListPage, Error>> + Send;

    /// Focused status update + optional outcome merge. Refreshes
    /// `updated_at` to NOW. Returns `false` if the task doesn't
    /// exist (no error — callers treat as "stale id, drop").
    fn update_task_status(
        &self,
        task_id: &str,
        new_status: TaskStatus,
        outcome: Option<serde_json::Value>,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// Atomic `INSERT-OR-IGNORE` keyed on `task_id`. Race-safe via
    /// the PK uniqueness constraint:
    ///
    /// - On clean insert returns
    ///   [`ClaimResult::Stored`]`(task)` with the row this caller
    ///   just wrote.
    /// - On conflict returns [`ClaimResult::AlreadyClaimed`]`(task)`
    ///   carrying the EXISTING row (re-read from the DB after the
    ///   INSERT no-op). Both arms reference the same `task_id`.
    fn try_claim_shared_task(
        &self,
        task: Task,
    ) -> impl Future<Output = Result<ClaimResult<Task>, Error>> + Send;

    /// Delete by `task_id`. Returns `true` if a row was deleted,
    /// `false` on second call (idempotent). FK semantics: children
    /// pointing at this row REJECT the delete — caller deletes the
    /// subtree explicitly (children-first). On PG the FK is
    /// DEFERRABLE so a multi-statement transaction can clear the
    /// subtree in any order; on SQLite the FK is enforced
    /// immediately.
    fn delete_task(&self, task_id: &str) -> impl Future<Output = Result<bool, Error>> + Send;
}
