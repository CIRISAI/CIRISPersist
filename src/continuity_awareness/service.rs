//! `ContinuityAwarenessService` trait surface (v1.5.17,
//! CIRISPersist#59 #9).
//!
//! 3 methods. Same `impl Future<...> + Send` GAT pattern as the
//! rest of the v0.8.x / v1.x substrate traits.

use std::future::Future;

use super::types::ContinuityAwareness;
use super::Error;
use crate::ClaimResult;

/// Continuity-awareness substrate trait — absorbs CIRISAgent's
/// `continuity_awareness` table. Per-shutdown record giving the
/// next boot a "where did I leave off" surface.
pub trait ContinuityAwarenessService: Send + Sync {
    /// Record a shutdown event. `INSERT ... ON CONFLICT (id) DO
    /// NOTHING` — write-once per shutdown id. Returns
    /// [`ClaimResult::Stored`]`(record)` on race-winner (the
    /// caller's row was written), or
    /// [`ClaimResult::AlreadyClaimed`]`(record)` on race-loser
    /// (the EXISTING row is returned — the caller's INSERT was
    /// suppressed).
    ///
    /// The `(preservation_node_id, preservation_scope)` pair MUST
    /// reference an existing `cirisgraph.nodes` row — the
    /// cross-substrate FK is enforced at write time on both
    /// backends.
    fn record_shutdown(
        &self,
        record: ContinuityAwareness,
    ) -> impl Future<Output = Result<ClaimResult<ContinuityAwareness>, Error>> + Send;

    /// Get the most recent shutdown for an agent — used on next
    /// boot to surface "where did I leave off." Ordered by
    /// `shutdown_timestamp DESC`, `LIMIT 1`. Returns `None` when
    /// the agent has no recorded shutdowns.
    fn get_latest_shutdown(
        &self,
        agent_id: &str,
    ) -> impl Future<Output = Result<Option<ContinuityAwareness>, Error>> + Send;

    /// Increment `reactivation_count` on the most-recent
    /// non-terminal shutdown for the agent. Used when the agent
    /// successfully resumes from a non-terminal shutdown.
    ///
    /// Returns `true` when a row was updated; `false` when the
    /// agent has only terminal shutdowns or no shutdowns at all
    /// (callers treat as "nothing to reactivate" — not an error).
    fn record_reactivation(
        &self,
        agent_id: &str,
    ) -> impl Future<Output = Result<bool, Error>> + Send;
}
