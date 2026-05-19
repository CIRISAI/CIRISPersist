//! `ThoughtService` trait surface (v1.5.10, CIRISPersist#59 #2).
//!
//! 5 methods. Same `impl Future<...> + Send` GAT pattern as the
//! rest of v0.8.x / v1.x substrate traits.

use std::future::Future;

use super::types::{Thought, ThoughtCursor, ThoughtFilter, ThoughtListPage, ThoughtStatus};
use super::Error;

/// Agent thoughts substrate trait — absorbs CIRISAgent's `thoughts`
/// table write + read + state-update + tree-walk surface.
pub trait ThoughtService: Send + Sync {
    /// Idempotent upsert keyed on `thought_id`. Re-insert with the
    /// same data is a no-op; re-insert with differing data overwrites
    /// mutable columns (status, content, channel_id, thought_type,
    /// round_number, context, thought_depth, ponder_notes,
    /// final_action, parent_thought_id, agent_occurrence_id) while
    /// preserving `created_at` from the original row.
    fn upsert_thought(&self, thought: Thought) -> impl Future<Output = Result<(), Error>> + Send;

    /// Read one thought by id. Returns `None` if no matching row.
    fn get_thought(
        &self,
        thought_id: &str,
    ) -> impl Future<Output = Result<Option<Thought>, Error>> + Send;

    /// Cursor-paged listing. Newest-first by `updated_at`. Index
    /// dispatch:
    /// - `agent_occurrence_id` + `status` set → `thoughts_status_occurrence`
    /// - `source_task_id` set → `thoughts_task_recency`
    /// - other shapes → full scan + ORDER BY ... LIMIT
    fn list_thoughts(
        &self,
        filter: ThoughtFilter,
        cursor: Option<ThoughtCursor>,
        limit: i64,
    ) -> impl Future<Output = Result<ThoughtListPage, Error>> + Send;

    /// Focused status update + optional final_action merge.
    /// Refreshes `updated_at` to NOW. Returns `false` if the thought
    /// doesn't exist (no error — callers treat as "stale id, drop").
    ///
    /// `final_action` semantics mirror `update_task_status`'s
    /// outcome: `None` preserves the existing value;
    /// `Some(Value::Null)` overwrites with NULL;
    /// `Some(other)` writes the value into `final_action_json`.
    fn update_thought_status(
        &self,
        thought_id: &str,
        new_status: ThoughtStatus,
        final_action: Option<serde_json::Value>,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// Walk the `parent_thought_id` chain rooted at `thought_id`,
    /// returning the root thought + every transitive descendant. Uses
    /// a `WITH RECURSIVE` CTE on both backends.
    ///
    /// # Ordering
    ///
    /// `thought_depth ASC, thought_id ASC`. Depth-first by tree
    /// structure with id tiebreak so the result is deterministic
    /// regardless of insertion order.
    ///
    /// # Empty result
    ///
    /// Returns an empty `Vec` (NOT [`Error::NotFound`]) when the
    /// root id has no matching row. Mirrors `list_thoughts`'s
    /// "empty result is empty page" convention.
    fn get_descendants(
        &self,
        thought_id: &str,
    ) -> impl Future<Output = Result<Vec<Thought>, Error>> + Send;

    /// Delete by `thought_id`. Returns `true` if a row was deleted,
    /// `false` on second call (idempotent). FK semantics mirror
    /// `delete_task`: the self-FK on `parent_thought_id` REJECTS the
    /// delete if children exist — caller deletes the subtree
    /// explicitly (leaves-first), or calls [`Self::get_descendants`]
    /// to enumerate before issuing deletes. The cascade on
    /// `source_task_id` (V035) is one-way: `task_delete` on a parent
    /// cascades thoughts; `thought_delete` does not touch tasks.
    fn delete_thought(&self, thought_id: &str) -> impl Future<Output = Result<bool, Error>> + Send;
}
