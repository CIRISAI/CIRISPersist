//! `ScheduledTaskService` trait surface (v1.5.12, CIRISPersist#59 #4).
//!
//! 3 methods. Same `impl Future<...> + Send` GAT pattern as the rest
//! of the v0.8.x / v1.x substrate traits.

use std::future::Future;

use chrono::{DateTime, Utc};

use super::types::{ScheduledTask, ScheduledTaskStatus};
use super::Error;

/// Scheduled tasks substrate trait — absorbs CIRISAgent's
/// `scheduled_tasks` table.
pub trait ScheduledTaskService: Send + Sync {
    /// Upsert a scheduled task. INSERT on first call, UPDATE on
    /// conflict by `id`. Every column except `created_at` is
    /// overwritten on re-upsert; `created_at` stays at its original
    /// value so the row's creation time isn't clobbered.
    fn upsert_scheduled_task(
        &self,
        task: ScheduledTask,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Hot-path query for the scheduler tick. Returns tasks where
    /// `next_trigger_at <= now` AND status IN (`PENDING`, `ACTIVE`),
    /// filtered by occurrence. Ordered by `next_trigger_at` ASC for
    /// fair scheduling. `limit` bounds the batch size (typical 100).
    /// Hits the `scheduled_tasks_due` partial index.
    fn list_due_scheduled_tasks(
        &self,
        agent_occurrence_id: &str,
        now: DateTime<Utc>,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<ScheduledTask>, Error>> + Send;

    /// Update `last_triggered_at` + `next_trigger_at` +
    /// `deferral_count` + `deferral_history` after the scheduler
    /// fires. Status transition is optional: `None` is a no-op on
    /// status; `Some(new_status)` advances the lifecycle. Returns
    /// `false` if the task didn't exist.
    ///
    /// `next_trigger_at` / `deferral_history` semantics: the caller
    /// passes the value the row should land at. Persist does not
    /// merge — callers reconstruct prior history client-side and
    /// pass the full updated value. `None` for `next_trigger_at`
    /// writes NULL (use this to mark a one-shot task as no longer
    /// scheduled).
    fn update_after_trigger(
        &self,
        task_id: &str,
        last_triggered_at: DateTime<Utc>,
        next_trigger_at: Option<DateTime<Utc>>,
        deferral_count: i32,
        deferral_history: Option<serde_json::Value>,
        new_status: Option<ScheduledTaskStatus>,
    ) -> impl Future<Output = Result<bool, Error>> + Send;
}
