//! `MaintenanceLockService` trait surface (v1.5.15,
//! CIRISPersist#59 #7).
//!
//! 3 methods. Same `impl Future<...> + Send` GAT pattern as the
//! rest of the v0.8.x / v1.x substrate traits.

use std::future::Future;

use super::types::MaintenanceLock;
use super::Error;

/// Maintenance-locks substrate trait — generic `lock_key`-keyed
/// multi-occurrence coordination primitive. Absorbs (and generalizes)
/// CIRISAgent's `consolidation_locks` table per CIRISPersist#59 #7.
pub trait MaintenanceLockService: Send + Sync {
    /// Atomic try-acquire. Returns `Some(MaintenanceLock)` on win
    /// (or when re-acquiring an expired lock); `None` when held by
    /// another active holder.
    ///
    /// Race-safe: implemented as a single-statement UPSERT with a
    /// WHERE clause filtering for "not held OR expired" so two
    /// concurrent callers cannot both observe the lock as available
    /// and both succeed.
    ///
    /// PG shape (see `postgres.rs`):
    ///   ```ignore
    ///   INSERT INTO cirislens.maintenance_locks (
    ///       lock_key, locked_by, locked_at, lock_timeout_seconds, metadata
    ///   ) VALUES ($1, $2, NOW(), $3, $4)
    ///   ON CONFLICT (lock_key) DO UPDATE SET
    ///       locked_by            = EXCLUDED.locked_by,
    ///       locked_at            = EXCLUDED.locked_at,
    ///       lock_timeout_seconds = EXCLUDED.lock_timeout_seconds,
    ///       metadata             = EXCLUDED.metadata
    ///   WHERE maintenance_locks.locked_by IS NULL
    ///      OR maintenance_locks.locked_at IS NULL
    ///      OR maintenance_locks.locked_at
    ///         + (maintenance_locks.lock_timeout_seconds * interval '1 second')
    ///         < NOW()
    ///   RETURNING …;
    ///   ```
    /// SQLite shape: `INSERT INTO … ON CONFLICT (lock_key) DO UPDATE
    /// SET … WHERE …` using `julianday('now')` arithmetic.
    ///
    /// Both backends server-stamp `locked_at` (NOW() / current_timestamp
    /// with subsec) so the "is this lock expired?" comparison is
    /// always against the same clock that wrote it.
    ///
    /// Returns `None` when the UPSERT's WHERE rejected the update
    /// (an active, unexpired lock is held by a different
    /// `locked_by`). Returns `Some(MaintenanceLock)` with the
    /// post-acquire row state when the caller now holds the lock.
    ///
    /// Re-acquiring under the SAME `locked_by` is treated as a
    /// refresh and succeeds — the WHERE clause uses
    /// `locked_by IS NULL OR expired`, but on the SQLite arm we
    /// additionally accept "same holder" as a refresh path so
    /// callers can extend their hold without releasing first. The
    /// PG arm gets the same behavior via the `locked_by =
    /// EXCLUDED.locked_by` overlap.
    fn try_acquire_lock(
        &self,
        lock_key: &str,
        locked_by: &str,
        timeout_seconds: i32,
        metadata: Option<serde_json::Value>,
    ) -> impl Future<Output = Result<Option<MaintenanceLock>, Error>> + Send;

    /// Release lock IFF the caller still holds it (i.e. the row's
    /// `locked_by` matches the supplied `locked_by`). Sets
    /// `locked_by` and `locked_at` back to NULL.
    ///
    /// Returns `true` when the row was released; `false` when no
    /// matching row exists, or the row is held by someone else
    /// (no-op — caller treats `false` as "not yours to release").
    fn release_lock(
        &self,
        lock_key: &str,
        locked_by: &str,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// Read current lock state. Returns `None` when the row doesn't
    /// exist (no caller has ever touched `lock_key`). Returns
    /// `Some(MaintenanceLock)` with current fields otherwise —
    /// caller checks [`MaintenanceLock::is_expired`] for staleness.
    fn get_lock(
        &self,
        lock_key: &str,
    ) -> impl Future<Output = Result<Option<MaintenanceLock>, Error>> + Send;
}
