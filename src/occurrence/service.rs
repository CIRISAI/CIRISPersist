//! `OccurrenceService` trait surface (v1.7.3, CIRISPersist#81).
//!
//! 4 methods. Same `impl Future<...> + Send` GAT pattern as the rest
//! of the v0.8.x / v1.x substrate traits.

use std::future::Future;

use super::types::OccurrenceRecord;
use super::Error;

/// Occurrence registration + liveness heartbeat substrate trait.
///
/// Backs the CIRIS 3.0 one-key model: every occurrence of an agent
/// signs with one Ed25519 identity, so occurrence churn is endpoint
/// liveness under a stable identity, not membership change. This
/// trait is the authoritative, TTL-based "which endpoints for
/// identity X are reachable right now" registry.
pub trait OccurrenceService: Send + Sync {
    /// Register (or re-register) an occurrence. Idempotent on
    /// occurrence_id — re-registering refreshes registered_at,
    /// last_heartbeat, expires_at. `ttl_seconds` must be > 0;
    /// expires_at = now + ttl_seconds.
    fn register_occurrence(
        &self,
        occurrence_id: &str,
        identity: &str,
        ttl_seconds: i64,
        metadata: Option<serde_json::Value>,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Bump last_heartbeat = now and expires_at = now + ttl_seconds
    /// for an already-registered occurrence. Returns false if the
    /// occurrence_id is not in the registry (caller should
    /// register_occurrence first — a heartbeat for an unknown
    /// occurrence is a no-op, not an error). ttl_seconds must be > 0.
    fn heartbeat_occurrence(
        &self,
        occurrence_id: &str,
        ttl_seconds: i64,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// Clean shutdown — remove the occurrence row immediately
    /// (don't wait for TTL expiry). Returns true if a row was
    /// removed, false if it wasn't registered. Idempotent.
    fn deregister_occurrence(
        &self,
        occurrence_id: &str,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// List currently-live occurrences for `identity` — rows whose
    /// expires_at > now. Ordered by occurrence_id ASC. Expired rows
    /// are filtered out (not deleted — a later prune or re-register
    /// handles cleanup; keep this method read-only).
    fn list_live_occurrences(
        &self,
        identity: &str,
    ) -> impl Future<Output = Result<Vec<OccurrenceRecord>, Error>> + Send;
}
