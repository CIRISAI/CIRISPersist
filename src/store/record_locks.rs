//! v54.0.0 (Codex on PR #1050) — **a striped in-process lock keyed on a
//! record's identity.**
//!
//! `signed_wire_index` maps a record's CURRENT content hash to its record
//! key, and a re-index reads the stored bytes, then replaces the mapping. Two
//! re-indexes of one record that interleave (a re-index whose read predates a
//! newer write, or two whose prune and insert cross) leave a stale hash
//! advertised that a point read rejects. Each backend therefore holds the
//! record's stripe from the read through the replacement; postgres also takes
//! a transaction-scoped advisory lock on the same identity, because other
//! processes write the same table.
//!
//! Striped, not one lock per record: a fixed set of mutexes, picked by a hash
//! of the identity, so unrelated records rarely wait on each other and the
//! table never grows.

use std::hash::{Hash, Hasher};

/// The stripe count. A power of two; contention needs two records to share a
/// stripe AND be re-indexed at the same instant.
const STRIPES: usize = 64;

/// See the module doc.
pub(crate) struct RecordLocks {
    stripes: Box<[tokio::sync::Mutex<()>]>,
}

impl Default for RecordLocks {
    fn default() -> Self {
        Self {
            stripes: (0..STRIPES).map(|_| tokio::sync::Mutex::new(())).collect(),
        }
    }
}

impl RecordLocks {
    /// Hold the stripe for `(kind, record_key)`.
    pub(crate) async fn lock(
        &self,
        kind: &str,
        record_key: &str,
    ) -> tokio::sync::MutexGuard<'_, ()> {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        (kind, record_key).hash(&mut h);
        let i = (h.finish() as usize) % self.stripes.len();
        self.stripes[i].lock().await
    }
}
