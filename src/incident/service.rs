//! `IncidentService` trait surface (v0.8.3, CIRISPersist#37).
//!
//! 4 methods. Same `impl Future<...> + Send` GAT pattern as the
//! rest of v0.8.x.

use std::future::Future;

use super::types::{
    Incident, IncidentCursor, IncidentFilter, IncidentListPage, IncidentRef, IncidentTransition,
};
use super::Error;

/// Incident-management write + read + state-transition surface
/// absorbed from CIRISAgent's IncidentManagementService.
pub trait IncidentService: Send + Sync {
    /// Record an incident. Correlation-keyed dedup:
    /// - If any OPEN/INVESTIGATING incident for `(tenant_id,
    ///   category)` shares at least one entry in
    ///   `correlation_keys`, that incident's `occurrences` is
    ///   bumped and `last_seen_at` is refreshed to NOW; the
    ///   `incident.incident_id` you passed in is ignored.
    /// - Otherwise a new row lands at `state = open, occurrences =
    ///   1`.
    ///
    /// Returns the `incident_id` of the row that took the write —
    /// either your supplied id (new) or the matched existing one
    /// (deduplicated).
    ///
    /// AV-56: rejects with `Error::InvalidArgument` when
    /// `correlation_keys.len() > MAX_CORRELATION_KEYS` or any key's
    /// byte-length exceeds `MAX_CORRELATION_KEY_BYTES`.
    fn record_incident(
        &self,
        incident: Incident,
    ) -> impl Future<Output = Result<String, Error>> + Send;

    /// AV-55: advance one incident along the state ladder
    /// (`Open → Investigating → Resolved → Closed`). Regressive or
    /// same-state transitions reject as `Error::InvalidTransition`.
    /// `resolution_notes` is REQUIRED when transitioning to
    /// `Resolved` or `Closed`.
    fn transition_state(
        &self,
        transition: IncidentTransition,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Cursor-paged tenant-scoped listing. Newest-first by
    /// `first_seen_at`.
    fn list_incidents(
        &self,
        filter: IncidentFilter,
        cursor: Option<IncidentCursor>,
        limit: i64,
    ) -> impl Future<Output = Result<IncidentListPage, Error>> + Send;

    /// Reverse-lookup: incidents that name a given key in their
    /// `correlation_keys` for one tenant. GIN-indexed; useful when
    /// a caller has e.g. a `node_id` and wants to know "which
    /// incidents reference this row?".
    fn correlate(
        &self,
        tenant_id: &str,
        key: &str,
    ) -> impl Future<Output = Result<Vec<IncidentRef>, Error>> + Send;
}
