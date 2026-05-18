//! `FeedbackMappingService` trait surface (v1.5.18,
//! CIRISPersist#59 #10).
//!
//! 3 methods. Same `impl Future<...> + Send` GAT pattern as the
//! rest of the v0.8.x / v1.x substrate traits.

use std::future::Future;

use super::types::{FeedbackFilter, FeedbackMapping};
use super::Error;
use crate::ClaimResult;

/// Feedback-mappings substrate trait — absorbs CIRISAgent's
/// `feedback_mappings` table. Per-feedback-id link between an
/// inbound wire-message and the thought it resolved against.
pub trait FeedbackMappingService: Send + Sync {
    /// Record a feedback row. `INSERT ... ON CONFLICT (feedback_id)
    /// DO NOTHING` — write-once per feedback id. Returns
    /// [`ClaimResult::Stored`]`(row)` on race-winner (the caller's
    /// row was written), or [`ClaimResult::AlreadyClaimed`]`(row)`
    /// on race-loser (the EXISTING row is returned — the caller's
    /// INSERT was suppressed).
    ///
    /// When `target_thought_id` is `Some(_)`, the referenced
    /// thought MUST exist or the FK fires (PG: `SqlState::
    /// FOREIGN_KEY_VIOLATION` → `Error::Conflict`; SQLite:
    /// extended code 787 → `Error::Conflict`). When `None`, the
    /// FK doesn't fire — both backends pass NULL FKs natively.
    fn record_feedback(
        &self,
        feedback: FeedbackMapping,
    ) -> impl Future<Output = Result<ClaimResult<FeedbackMapping>, Error>> + Send;

    /// List feedback rows attached to a specific thought. Ordered
    /// `created_at DESC`. Hits the partial index
    /// `feedback_mappings_thought`.
    fn list_feedback_for_thought(
        &self,
        thought_id: &str,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<FeedbackMapping>, Error>> + Send;

    /// Filter query — by feedback_type, source_message_id, and/or
    /// time window. Ordered DESC by `created_at`.
    fn list_feedback(
        &self,
        filter: FeedbackFilter,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<FeedbackMapping>, Error>> + Send;
}
