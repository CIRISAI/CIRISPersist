//! `ServiceTokenRevocationService` trait surface (v1.5.23,
//! CIRISPersist#64).
//!
//! 3 methods. Same `impl Future<...> + Send` GAT pattern as the
//! rest of the v0.8.x / v1.x substrate traits.

use std::future::Future;

use super::types::RevokedServiceToken;
use super::Error;

/// Service-token revocation substrate trait — absorbs CIRISAgent's
/// standalone `revoked_service_tokens.db` (the last aiosqlite
/// consumer in the agent).
pub trait ServiceTokenRevocationService: Send + Sync {
    /// Idempotent upsert keyed on `token_hash`. Re-record with same
    /// `token_hash` is a no-op (PK conflict resolved via
    /// `ON CONFLICT DO NOTHING` — caller can retry safely). The
    /// first record wins; subsequent records with the same hash
    /// are ignored (revocation timestamp + reason are stable once
    /// recorded).
    fn record_revocation(
        &self,
        revocation: RevokedServiceToken,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Full table dump — agent caches in memory on startup. Order
    /// is unspecified (caller uses `HashSet` / dict). Returns empty
    /// `Vec` on cold table (not an error).
    fn list_revocations(
        &self,
    ) -> impl Future<Output = Result<Vec<RevokedServiceToken>, Error>> + Send;

    /// Point-lookup check. Returns the row if revoked, `None`
    /// otherwise. Backed by the PRIMARY KEY index.
    fn check_revocation(
        &self,
        token_hash: &str,
    ) -> impl Future<Output = Result<Option<RevokedServiceToken>, Error>> + Send;
}
