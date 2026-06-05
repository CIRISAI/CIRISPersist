//! Cache observability — atomic-backed counters.
//!
//! FSD V4.0 §7.2: every cached aggregate is accounted for so a
//! cohabiting peer's `cache_stats()` answers "what's hot in this
//! peer's read path right now" across every consumer. Counters are
//! atomic so the hot read path can increment without taking the cache
//! mutex for accounting purposes.

use std::sync::atomic::{AtomicU64, Ordering};

/// Internal atomic-backed counter set. Lives inside [`super::Cache`];
/// callers observe a consistent snapshot via [`AtomicCacheStats::snapshot`]
/// which materializes the plain [`CacheStats`] struct.
#[derive(Debug, Default)]
pub(crate) struct AtomicCacheStats {
    hits: AtomicU64,
    misses: AtomicU64,
    evictions_lru: AtomicU64,
    evictions_ttl: AtomicU64,
    invalidations_write: AtomicU64,
    bytes_resident: AtomicU64,
    entries_resident: AtomicU64,
}

impl AtomicCacheStats {
    pub(crate) fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_eviction_lru(&self, n: u64) {
        if n > 0 {
            self.evictions_lru.fetch_add(n, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_eviction_ttl(&self, n: u64) {
        if n > 0 {
            self.evictions_ttl.fetch_add(n, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_invalidation_write(&self, n: u64) {
        if n > 0 {
            self.invalidations_write.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Set the gauges that track live residency. These are absolute
    /// values (not deltas) recomputed from the LRU under the cache
    /// mutex; they are gauges, not counters.
    pub(crate) fn set_residency(&self, bytes_resident: u64, entries_resident: u64) {
        self.bytes_resident.store(bytes_resident, Ordering::Relaxed);
        self.entries_resident
            .store(entries_resident, Ordering::Relaxed);
    }

    /// Materialize a consistent-enough snapshot. Counters are read
    /// independently (relaxed); the snapshot is monotone per-field but
    /// not a single atomic instant — this matches the observability
    /// contract (stats are advisory, not load-bearing for correctness).
    pub(crate) fn snapshot(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions_lru: self.evictions_lru.load(Ordering::Relaxed),
            evictions_ttl: self.evictions_ttl.load(Ordering::Relaxed),
            invalidations_write: self.invalidations_write.load(Ordering::Relaxed),
            bytes_resident: self.bytes_resident.load(Ordering::Relaxed),
            entries_resident: self.entries_resident.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of substrate-cache observability counters (FSD V4.0 §7.2).
///
/// `hits` / `misses` are the cardinal read-path counters; eviction is
/// split between LRU / size pressure ([`CacheStats::evictions_lru`])
/// and TTL expiry ([`CacheStats::evictions_ttl`]) so an operator can
/// tell "cache is too small" from "TTL is too short."
/// `invalidations_write` counts entries dropped by the §7.3
/// window-overlap bucket invalidation. `bytes_resident` /
/// `entries_resident` are live gauges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CacheStats {
    /// Reads served from a live (non-expired) cache entry.
    pub hits: u64,
    /// Reads that fell through to the compute path (entry absent or
    /// TTL-expired).
    pub misses: u64,
    /// Entries dropped under capacity pressure (LRU tail eviction —
    /// either `max_entries` or `max_bytes` bound hit first).
    pub evictions_lru: u64,
    /// Entries dropped because their TTL fired before they were read.
    pub evictions_ttl: u64,
    /// Entries dropped by §7.3 write-driven, window-overlap bucket
    /// invalidation.
    pub invalidations_write: u64,
    /// Approximate bytes resident in the cache (sum of entry
    /// `byte_size`s).
    pub bytes_resident: u64,
    /// Number of entries currently resident.
    pub entries_resident: u64,
}
