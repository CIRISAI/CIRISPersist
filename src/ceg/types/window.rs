//! [`TimeWindow`] — the `(since, until)` pair used by every windowed
//! read primitive (sections E / F / G / H).
//!
//! Moved from `src/read/types.rs` in v4.0 (FSD §3.3). No behaviour
//! change — the v3.x `crate::read::TimeWindow` path stays valid through
//! the `crate::read` façade shim.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Half-open time window `[since, until)`.
///
/// All windowed primitives take a [`TimeWindow`] rather than separate
/// `since`/`until` parameters to make "filter by time" a single typed
/// argument. AV-4 caveat: window-filter inputs are caller-provided
/// wall-clock; the time-bound assertion is best-effort, not
/// authenticated. Documented on every windowed primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Inclusive lower bound.
    pub since: DateTime<Utc>,
    /// Exclusive upper bound.
    pub until: DateTime<Utc>,
}

impl TimeWindow {
    /// Construct + validate. Returns
    /// [`crate::ceg::Error::InvalidArgument`] if `since >= until`.
    pub fn new(since: DateTime<Utc>, until: DateTime<Utc>) -> Result<Self, crate::ceg::Error> {
        if since >= until {
            return Err(crate::ceg::Error::InvalidArgument(format!(
                "TimeWindow: since ({since}) must be < until ({until})"
            )));
        }
        Ok(TimeWindow { since, until })
    }

    /// Window duration.
    pub fn duration(&self) -> chrono::Duration {
        self.until - self.since
    }
}
