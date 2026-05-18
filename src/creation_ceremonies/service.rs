//! `CreationCeremonyService` trait surface (v1.5.16,
//! CIRISPersist#59 #8).
//!
//! 4 methods. Same `impl Future<...> + Send` GAT pattern as the
//! rest of the v0.8.x / v1.x substrate traits.

use std::future::Future;

use super::types::{CeremonyFilter, CeremonyStatus, CreationCeremony};
use super::Error;
use crate::ClaimResult;

/// Creation-ceremonies substrate trait — absorbs CIRISAgent's
/// `creation_ceremonies` table. Identity-creation history, write-
/// once-mostly with a focused status transition path.
pub trait CreationCeremonyService: Send + Sync {
    /// Record a ceremony. INSERT ON CONFLICT (ceremony_id) DO
    /// NOTHING — write-once shape. Returns
    /// [`ClaimResult::Stored`]`(ceremony)` on race-winner (the
    /// caller's row was written), or
    /// [`ClaimResult::AlreadyClaimed`]`(ceremony)` on race-loser
    /// (the EXISTING row is returned — the caller's INSERT was
    /// suppressed and the original row's data is preserved).
    fn record_ceremony(
        &self,
        ceremony: CreationCeremony,
    ) -> impl Future<Output = Result<ClaimResult<CreationCeremony>, Error>> + Send;

    /// Point lookup. Returns `None` when no matching row.
    fn get_ceremony(
        &self,
        ceremony_id: &str,
    ) -> impl Future<Output = Result<Option<CreationCeremony>, Error>> + Send;

    /// History query. Filter by creator / WA / new_agent / status /
    /// time window. Ordered by `timestamp DESC, ceremony_id DESC`
    /// (timestamp ties broken by ceremony_id for deterministic
    /// pagination), limited.
    ///
    /// Index dispatch — see `CeremonyFilter` doc.
    fn list_ceremonies(
        &self,
        filter: CeremonyFilter,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<CreationCeremony>, Error>> + Send;

    /// Atomic state advance: set `ceremony_status` to `new_status`.
    /// Returns `true` when the row was updated; `false` when no
    /// matching row (no error — callers treat as stale id).
    ///
    /// Ceremonies are typically write-once, but the status field
    /// transitions across the lifecycle (`pending` → `in_progress`
    /// → `completed`/`failed`/`revoked`) so this focused method
    /// avoids a full UPSERT for the status-only update path.
    fn update_ceremony_status(
        &self,
        ceremony_id: &str,
        new_status: CeremonyStatus,
    ) -> impl Future<Output = Result<bool, Error>> + Send;
}
