//! `DeferralReportService` trait surface (v1.5.14,
//! CIRISPersist#59 #6).
//!
//! 4 methods. Same `impl Future<...> + Send` GAT pattern as the
//! rest of the v0.8.x / v1.x substrate traits.

use std::future::Future;

use chrono::{DateTime, Utc};

use super::types::{DeferralFilter, DeferralReport};
use super::Error;
use crate::ClaimResult;

/// Deferral-reports substrate trait — absorbs CIRISAgent's
/// `deferral_reports` table.
pub trait DeferralReportService: Send + Sync {
    /// Record a new deferral report. INSERT OR IGNORE on
    /// `message_id` — idempotent re-record. On race-winner the
    /// caller's row is stored and returned as
    /// [`ClaimResult::Stored`]`(report)`; on race-loser the
    /// EXISTING row is returned as
    /// [`ClaimResult::AlreadyClaimed`]`(report)`.
    ///
    /// FK semantics: `task_id` must reference an existing row in
    /// `cirislens.tasks`, and `thought_id` must reference an
    /// existing row in `cirislens.thoughts`. PG: both FKs are
    /// `DEFERRABLE INITIALLY DEFERRED` so a single tx can write
    /// `(task, thought, deferral_report)` in order. SQLite: FKs
    /// are immediate; agent callers handle ordering at the trait
    /// surface.
    fn record_deferral(
        &self,
        report: DeferralReport,
    ) -> impl Future<Output = Result<ClaimResult<DeferralReport>, Error>> + Send;

    /// Point lookup. Returns `None` when no matching row.
    fn get_deferral(
        &self,
        message_id: &str,
    ) -> impl Future<Output = Result<Option<DeferralReport>, Error>> + Send;

    /// List deferrals awaiting WA resolution (`resolved_at IS NULL`).
    /// Newest-first by `created_at`. Optional narrowing via
    /// `filter.task_id` / `filter.thought_id` (NOT NULL FKs — direct
    /// equality) and `filter.created_after` / `filter.created_before`
    /// (time window).
    fn list_active_deferrals(
        &self,
        filter: DeferralFilter,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<DeferralReport>, Error>> + Send;

    /// Mark a deferral as resolved. Sets `resolved_at` to the
    /// supplied timestamp and `resolution_notes` to the supplied
    /// value (overwrites — `None` clears). Returns `false` when
    /// the row doesn't exist (no error — callers treat as stale
    /// id, drop). Returns `true` on a successful update.
    fn resolve_deferral(
        &self,
        message_id: &str,
        resolved_at: DateTime<Utc>,
        resolution_notes: Option<String>,
    ) -> impl Future<Output = Result<bool, Error>> + Send;
}
