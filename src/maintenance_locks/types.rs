//! Maintenance-locks substrate wire types (v1.5.15,
//! CIRISPersist#59 #7).
//!
//! Mirrors the row shape of `cirislens.maintenance_locks` (Postgres)
//! / `cirislens_maintenance_locks` (SQLite). JSON column `metadata`
//! lifts to `serde_json::Value` (Postgres maps it as JSONB; SQLite
//! stores it as TEXT). The lock model is "row-as-mutex":
//!
//!   * `lock_key` — caller-supplied identifier (PK).
//!   * `locked_by` — owner token; NULL when nobody holds.
//!   * `locked_at` — wall-clock acquire time; NULL when nobody holds.
//!   * `lock_timeout_seconds` — TTL after `locked_at`; expired locks
//!     become eligible for steal-the-stale acquire.
//!   * `metadata` — optional caller-supplied JSON payload (worker id,
//!     occurrence id, etc.).

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Default lock-timeout seconds (mirrors the agent's
/// `lock_timeout_seconds INTEGER DEFAULT 300` SQLite column).
pub const DEFAULT_LOCK_TIMEOUT_SECONDS: i32 = 300;

/// One row of the `maintenance_locks` substrate.
///
/// 5 columns. Agent ships 4: `lock_key` (PK), `locked_by`,
/// `locked_at`, `lock_timeout_seconds`. Persist adds 1 nullable
/// column: `metadata`, supporting lock-holder context (worker id,
/// occurrence id, etc.) for operator observability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MaintenanceLock {
    /// Caller-supplied lock identifier. NOT NULL, PK.
    pub lock_key: String,
    /// Owner token (e.g. worker id). `None` when no holder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_by: Option<String>,
    /// Wall-clock acquire time. `None` when no holder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_at: Option<DateTime<Utc>>,
    /// TTL after `locked_at` (seconds). Defaults to 300; CHECK
    /// constraint enforces `> 0`.
    pub lock_timeout_seconds: i32,
    /// Optional caller-supplied JSON payload. Persist-only column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl MaintenanceLock {
    /// Returns `true` when this lock is not actively held by anyone
    /// — i.e. eligible for [`super::service::MaintenanceLockService::try_acquire_lock`].
    ///
    /// "Not held" means:
    ///   * `locked_by` is `None`, OR
    ///   * `locked_at` is `None` (defensive — both nullable columns
    ///     should move in lockstep, but treat either NULL as "no
    ///     holder"), OR
    ///   * `now > locked_at + lock_timeout_seconds`
    ///
    /// The `now` argument is caller-supplied so backends can use the
    /// same wall-clock moment for race-safe comparison. PG uses
    /// `NOW()` server-side in the UPSERT WHERE clause; SQLite uses
    /// `julianday('now')` server-side. Both should agree with the
    /// caller's `now` for any single wall-clock moment.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        match (self.locked_by.as_ref(), self.locked_at) {
            (None, _) | (_, None) => true,
            (Some(_), Some(at)) => {
                let timeout = chrono::Duration::seconds(self.lock_timeout_seconds.into());
                now > at + timeout
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(
        locked_by: Option<&str>,
        locked_at: Option<DateTime<Utc>>,
        timeout: i32,
    ) -> MaintenanceLock {
        MaintenanceLock {
            lock_key: "k".into(),
            locked_by: locked_by.map(str::to_owned),
            locked_at,
            lock_timeout_seconds: timeout,
            metadata: None,
        }
    }

    #[test]
    fn is_expired_nothing_held_locked_by_none() {
        let now = Utc::now();
        let l = mk(None, Some(now), 300);
        assert!(l.is_expired(now), "locked_by=None means not held → expired");
    }

    #[test]
    fn is_expired_nothing_held_locked_at_none() {
        let now = Utc::now();
        let l = mk(Some("worker-a"), None, 300);
        assert!(l.is_expired(now), "locked_at=None means not held → expired");
    }

    #[test]
    fn is_expired_active_lock_fresh() {
        let now = Utc::now();
        let l = mk(Some("worker-a"), Some(now), 300);
        assert!(!l.is_expired(now), "just-acquired lock is not expired");
    }

    #[test]
    fn is_expired_active_lock_inside_window() {
        let now = Utc::now();
        // Acquired 100s ago, 300s timeout — still active.
        let acquired = now - chrono::Duration::seconds(100);
        let l = mk(Some("worker-a"), Some(acquired), 300);
        assert!(!l.is_expired(now), "100s into 300s timeout is not expired");
    }

    #[test]
    fn is_expired_active_lock_past_window() {
        let now = Utc::now();
        // Acquired 400s ago, 300s timeout — expired.
        let acquired = now - chrono::Duration::seconds(400);
        let l = mk(Some("worker-a"), Some(acquired), 300);
        assert!(l.is_expired(now), "400s past 300s timeout is expired");
    }

    #[test]
    fn lock_serde_round_trip_all_columns() {
        let now = Utc::now();
        let l = MaintenanceLock {
            lock_key: "tsdb_consolidation".into(),
            locked_by: Some("worker-7".into()),
            locked_at: Some(now),
            lock_timeout_seconds: 300,
            metadata: Some(serde_json::json!({"occurrence_id": "occ-1", "pid": 12345})),
        };
        let s = serde_json::to_string(&l).unwrap();
        let back: MaintenanceLock = serde_json::from_str(&s).unwrap();
        assert_eq!(l, back);
    }

    #[test]
    fn lock_serde_minimal_agent_shape_back_compat() {
        // Agent's 4-column shape — no metadata. Should deserialize
        // cleanly with metadata=None default.
        let json = serde_json::json!({
            "lock_key": "k",
            "locked_by": null,
            "locked_at": null,
            "lock_timeout_seconds": 300,
        });
        let l: MaintenanceLock = serde_json::from_value(json).unwrap();
        assert!(l.metadata.is_none());
        assert_eq!(l.lock_timeout_seconds, 300);
    }

    #[test]
    fn lock_serde_omits_metadata_when_none() {
        let l = MaintenanceLock {
            lock_key: "k".into(),
            locked_by: None,
            locked_at: None,
            lock_timeout_seconds: 300,
            metadata: None,
        };
        let s = serde_json::to_string(&l).unwrap();
        assert!(
            !s.contains("metadata"),
            "None metadata omitted on serialize: {s}"
        );
        assert!(!s.contains("locked_by"));
        assert!(!s.contains("locked_at"));
    }

    #[test]
    fn default_timeout_matches_agent() {
        assert_eq!(DEFAULT_LOCK_TIMEOUT_SECONDS, 300);
    }
}
