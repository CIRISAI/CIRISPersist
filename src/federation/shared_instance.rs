//! SharedInstanceLease — cross-process leader election for a named
//! singleton (CIRISPersist#210, CIRISEdge#100).
//!
//! Multi-worker FastAPI/uvicorn deployments each call `init_edge_runtime`
//! and race to bind the same Reticulum UDP socket; all but one fail with
//! `EADDRINUSE`. The architecturally clean fix is RNS shared-instance
//! mode — one process owns the link-layer sockets, siblings attach over
//! an AF_UNIX socket and get full RNS semantics without binding. The only
//! missing piece is **leader election**: deciding which process is the
//! server. Persist already owns the canonical cross-process coordination
//! layer for the CIRIS family (cf. the revocation-quorum state), so this
//! is its right home: liveness is a heartbeat-age query (a flock can't
//! detect a crashed owner), the owner is operator-introspectable
//! (`SELECT * FROM shared_instance_leases`), and every consumer already
//! talks to persist (no new IPC channel).
//!
//! The election is a TTL lease: a process [`try_acquire`]s a named
//! instance; the winner becomes the server and
//! [`heartbeat`]s on a timer; if the owner pauses/crashes past the
//! staleness window, a sibling steals the lease (and the original owner
//! learns it was demoted when its next heartbeat returns `None`). The
//! atomicity that makes "exactly one winner" hold lives in the backends'
//! single-statement upsert — see [`FederationDirectory::try_acquire_shared_instance`].
//!
//! [`try_acquire`]: crate::federation::FederationDirectory::try_acquire_shared_instance
//! [`heartbeat`]: crate::federation::FederationDirectory::heartbeat_shared_instance
//! [`FederationDirectory::try_acquire_shared_instance`]: crate::federation::FederationDirectory::try_acquire_shared_instance

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Default staleness window: a lease whose `last_heartbeat_at` is older
/// than this is considered dead and stealable. Pairs with a ~10s
/// heartbeat cadence (3 missed beats before takeover).
pub const DEFAULT_STALE_AFTER: Duration = Duration::from_secs(30);

/// A lease over a named singleton instance (e.g. the Reticulum
/// shared-instance owner). Held for the lifetime of the owning process;
/// auto-released when the row's `last_heartbeat_at` ages past the
/// staleness window a sibling acquires with.
///
/// Serde-serializable so it round-trips the FFI boundary as JSON; the
/// owning process holds the returned value and passes it back to
/// [`heartbeat`](crate::federation::FederationDirectory::heartbeat_shared_instance)
/// / [`release`](crate::federation::FederationDirectory::release_shared_instance_lease).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedInstanceLease {
    /// The named singleton this lease is for (e.g. `"reticulum:default"`).
    pub instance_name: String,
    /// OS pid of the owning process. Diagnostic + lets an operator map a
    /// lease to a running process.
    pub owner_pid: i32,
    /// Hostname of the owning process. With `owner_pid`, uniquely
    /// identifies the owner for cross-host debugging.
    pub owner_hostname: String,
    /// When this owner most recently *acquired* (or stole) the lease.
    pub acquired_at: DateTime<Utc>,
    /// When the owner last proved liveness. Drives the staleness check.
    pub last_heartbeat_at: DateTime<Utc>,
    /// Increments on every acquire/steal. The heartbeat compares the
    /// stored version against the held one to detect a takeover: if the
    /// row's version has moved past ours, our lease was stolen while we
    /// were paused and we must demote to client.
    pub lease_version: i64,
}

/// The instant before which a `last_heartbeat_at` counts as stale. The
/// caller computes this client-side (= `now - stale_after`) and passes it
/// to the backend so the new row's timestamps and the staleness
/// comparison share one clock — no server/client clock-skew in the race.
#[must_use]
pub fn staleness_threshold(now: DateTime<Utc>, stale_after: Duration) -> DateTime<Utc> {
    now - chrono::Duration::from_std(stale_after).unwrap_or_else(|_| chrono::Duration::seconds(30))
}
