//! [`TraceCursor`] — opaque cursor for trace-summary listing (section A).
//!
//! Moved from `src/read/types.rs` in v4.0 (FSD §3.3). Other cursor
//! types (`TaskCursor`, `LlmCallCursor`, federation cursors) stay
//! co-located with their list primitives under `src/ceg/list/`; this
//! file holds the shared trace cursor the §A listing surface uses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Opaque cursor for [`crate::ceg::ReadEngine::list_trace_summaries`].
///
/// Built around the `(started_at, trace_id)` tuple — paged queries
/// order by `started_at DESC, trace_id DESC` (newest-first triage),
/// and the cursor encodes the last item's `(ts, trace_id)` so the
/// next page picks up at the next-older trace.
///
/// Wire-stable: serializes to JSON, the PyO3 boundary treats it as
/// an opaque string. Internal field shape may evolve in v0.5.x; the
/// JSON shape is the contract. v0.5.0 carries a `version` tag so
/// future evolutions can route by it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceCursor {
    /// Cursor format version. v0.5.0 ships `"v1"`. Future cursor
    /// shape evolutions add a new variant + this field discriminates.
    pub version: String,

    /// `started_at` of the last item on the previous page.
    pub last_started_at: DateTime<Utc>,

    /// `trace_id` of the last item — tiebreaker for traces with
    /// equal `started_at`.
    pub last_trace_id: String,
}

impl TraceCursor {
    /// Construct a v1 cursor from the trailing edge of a result page.
    pub fn from_trailing(last_started_at: DateTime<Utc>, last_trace_id: String) -> Self {
        TraceCursor {
            version: "v1".to_owned(),
            last_started_at,
            last_trace_id,
        }
    }
}
