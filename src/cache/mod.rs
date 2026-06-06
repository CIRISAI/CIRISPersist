//! The substrate caching primitive (FSD V4.0 §7).
//!
//! Eric's directive: *"caching should be a generic persist capability."*
//! One eviction policy, one observability surface, one staleness
//! contract for every read consumer cohabiting in a peer process
//! (§7.1). This module is the *generic* cache; wiring it into the
//! aggregate read primitives is Commit G's job — here we ship the
//! mechanism and its tests.
//!
//! Submodules:
//! - [`lru`] — the bounded `max_entries` + `max_bytes` + TTL LRU.
//! - [`key`] — [`CacheKey`] derivation + the §7.3 window-overlap bucket
//!   set (the #160-comment-2 correctness fix).
//! - [`stats`] — atomic-backed [`CacheStats`].
//! - [`admission`] — the §7.5 [`AdmissionCache`].

pub mod admission;
pub mod key;
pub mod lru;
pub mod stats;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub use admission::{AdmissionCache, AdmissionStats};
pub use key::{Bucket, CacheKey, IdentityKeyId, KeyId, OccurrenceKeyId};
pub use stats::CacheStats;

use lru::{CacheEntry, LruCache};
use stats::AtomicCacheStats;

/// Deployment tier — selects the default cache budget (§7.2). Derived
/// at compile time from `target_os` / `target_arch`, overridable at
/// construction by operators with tighter budgets.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeploymentTier {
    /// iOS / Android — ~8 MiB resident so the OS persistence budget
    /// isn't blown.
    Mobile,
    /// Small ARM (Raspberry-Pi-class) Linux — ~32 MiB.
    Edge,
    /// x86_64 / desktop / server — ~64 MiB.
    Server,
}

impl DeploymentTier {
    /// Compile-time default tier (§7.2). iOS/Android → [`Mobile`];
    /// arm/aarch64 Linux → [`Edge`]; everything else → [`Server`].
    /// Operator policy may override at [`Cache`] construction when a
    /// runtime tier indicator should win over `target_os`.
    ///
    /// [`Mobile`]: DeploymentTier::Mobile
    /// [`Edge`]: DeploymentTier::Edge
    /// [`Server`]: DeploymentTier::Server
    pub const fn compile_time_default() -> Self {
        if cfg!(any(target_os = "ios", target_os = "android")) {
            Self::Mobile
        } else if cfg!(any(target_arch = "arm", target_arch = "aarch64"))
            && cfg!(target_os = "linux")
        {
            // Best-effort heuristic for Pi-class edge; operator override
            // is still the source of truth.
            Self::Edge
        } else {
            Self::Server
        }
    }
}

/// Cache configuration (§7.2). Bounds + TTL + invalidation bucket. The
/// [`Default`] impl derives from [`DeploymentTier::compile_time_default`].
#[derive(Clone, Debug)]
pub struct CacheConfig {
    /// Hard cap on resident entries (LRU tail-evicts past this).
    pub max_entries: usize,
    /// Hard cap on resident bytes (sum of declared entry sizes).
    pub max_bytes: usize,
    /// Per-entry time-to-live. Default 30s for aggregates (§7.3).
    pub ttl: Duration,
    /// Window-overlap invalidation bucket width (§7.3). Default 1h.
    pub invalidation_bucket: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self::default_for_tier(DeploymentTier::compile_time_default())
    }
}

impl CacheConfig {
    /// The budget for a given deployment tier (§7.2). Mobile
    /// 8 MiB/256 entries, Edge 32 MiB/512, Server 64 MiB/1024 — all
    /// 30s TTL + 1h invalidation bucket.
    pub fn default_for_tier(tier: DeploymentTier) -> Self {
        match tier {
            DeploymentTier::Mobile => Self {
                max_entries: 256,
                max_bytes: 8 * 1024 * 1024,
                ttl: Duration::from_secs(30),
                invalidation_bucket: Duration::from_secs(3600),
            },
            DeploymentTier::Edge => Self {
                max_entries: 512,
                max_bytes: 32 * 1024 * 1024,
                ttl: Duration::from_secs(30),
                invalidation_bucket: Duration::from_secs(3600),
            },
            DeploymentTier::Server => Self {
                max_entries: 1024,
                max_bytes: 64 * 1024 * 1024,
                ttl: Duration::from_secs(30),
                invalidation_bucket: Duration::from_secs(3600),
            },
        }
    }
}

/// Locked interior — just the bounded LRU. Behind a single `Mutex`.
///
/// There is no longer a `bucket → set<CacheKey>` reverse index:
/// write-invalidation scans the resident keys and tests each one's
/// `[first_bucket, last_bucket]` range ([`LruCache::keys_overlapping_bucket`]).
/// The reverse index cost O(n²) memory because each key carried (and
/// each per-bucket clone re-carried) the full materialized bucket run
/// — a wide window OOM'd the process (CIRISConformance#11). The cache
/// is bounded (`max_entries` ≤ 1024) and writes are off the hot read
/// path, so the per-write scan is cheap and the per-key memory is O(1).
struct Inner<T> {
    lru: LruCache<T>,
}

/// The generic substrate cache (§7.2).
///
/// `T` is the cached payload type — for aggregates this is the result
/// struct. Read consumers call [`Cache::get_or_compute`]; write paths
/// call [`Cache::invalidate_write`] with the write timestamp. Staleness
/// is bounded by TTL and reported fail-honest (§7.4): a TTL-expired
/// entry is dropped, and if the recompute closure errors the cache
/// surfaces the real error and serves nothing stale.
pub struct Cache<T> {
    inner: Mutex<Inner<T>>,
    config: CacheConfig,
    stats: AtomicCacheStats,
}

impl<T> Cache<T> {
    /// Construct a cache with tier-derived defaults
    /// ([`CacheConfig::default`]).
    pub fn new() -> Self {
        Self::with_config(CacheConfig::default())
    }

    /// Construct a cache with an explicit config (operator override).
    pub fn with_config(config: CacheConfig) -> Self {
        Self {
            inner: Mutex::new(Inner {
                lru: LruCache::new(config.max_entries, config.max_bytes),
            }),
            config,
            stats: AtomicCacheStats::default(),
        }
    }

    /// The active configuration.
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    /// Snapshot of observability counters (§7.2). Exposed as a public
    /// Rust method here; the PyO3 `Engine.cache_stats()` binding lands
    /// in the FFI commit, not this one.
    pub fn stats(&self) -> CacheStats {
        self.stats.snapshot()
    }

    /// Refresh the residency gauges from the live LRU and return the
    /// snapshot. Cheap; takes the mutex once.
    fn refresh_residency(&self, inner: &Inner<T>) {
        self.stats
            .set_residency(inner.lru.bytes_resident() as u64, inner.lru.len() as u64);
    }

    /// Read-through: return a live cached value or compute, store, and
    /// return it. The single path to the backend (§7.3): on hit, the
    /// cached `Arc` is returned; on miss (absent or TTL-expired) the
    /// `compute` closure runs, its result is stored, and a clone is
    /// returned.
    ///
    /// **Fail-honest (§7.4):** when `compute` errors — e.g. TTL fired
    /// and the backend is unreachable — the error is returned verbatim
    /// and **nothing stale is served**. The expired entry has already
    /// been dropped by the `get` miss, so a subsequent successful call
    /// recomputes cleanly.
    ///
    /// `compute` is synchronous and returns `(value, byte_size)`. The
    /// substrate aggregate primitives wrap their async backend read
    /// behind this — Commit G owns that wiring; the cache itself stays
    /// runtime-agnostic.
    pub fn get_or_compute<E, F>(&self, key: CacheKey, compute: F) -> Result<Arc<T>, E>
    where
        F: FnOnce() -> Result<(T, usize), E>,
    {
        let now = Instant::now();
        let ttl = self.config.ttl;

        // Fast path: hit.
        {
            let mut inner = self.inner.lock().expect("cache mutex poisoned");
            let got = inner.lru.get(&key, ttl, now);
            if got.evicted_ttl > 0 {
                self.stats.record_eviction_ttl(got.evicted_ttl);
                // The TTL-expired entry was dropped from the LRU; refresh
                // the residency gauge so a subsequent fail-honest error
                // path leaves no phantom resident count (§7.4).
                self.refresh_residency(&inner);
            }
            if let Some(value) = got.hit {
                self.stats.record_hit();
                self.refresh_residency(&inner);
                return Ok(value);
            }
        }

        // Miss: compute outside the lock so a slow backend read doesn't
        // serialize the whole cache.
        // §7.4 fail-honest: on error we surface it verbatim and serve
        // nothing stale — the expired entry was already dropped above.
        self.stats.record_miss();
        let (value, byte_size) = compute()?;
        let value = Arc::new(value);

        let mut inner = self.inner.lock().expect("cache mutex poisoned");
        // Another caller may have populated this key while we computed;
        // last-writer-wins is fine (both computed fresh).
        let out = inner.lru.insert(
            key.clone(),
            CacheEntry {
                value: Arc::clone(&value),
                byte_size,
                inserted_at: now,
            },
        );
        if out.evicted_lru > 0 {
            self.stats.record_eviction_lru(out.evicted_lru);
        }
        self.refresh_residency(&inner);

        // Return the freshly computed value regardless of whether it
        // stayed resident — honest: a value too big to cache is still
        // returned, just uncached.
        Ok(value)
    }

    /// Read-only probe for an async caller (FSD §7.3 cache-miss path).
    ///
    /// [`get_or_compute`](Self::get_or_compute) takes a *synchronous*
    /// `FnOnce`; an aggregate read whose recompute is an `async` backend
    /// query cannot run it inside that closure. The async caller instead
    /// does: `try_get` (hit → return cached); on miss run the async query
    /// then [`store`](Self::store). This split records hits/misses and
    /// honours TTL identically to `get_or_compute` — a TTL-expired entry
    /// is dropped and reported as a miss (§7.4 fail-honest: nothing stale
    /// is returned; the caller recomputes).
    ///
    /// Returns `Some(Arc<T>)` on a live hit (records a hit), `None` on
    /// absent-or-expired (records a miss).
    pub fn try_get(&self, key: &CacheKey) -> Option<Arc<T>> {
        let now = Instant::now();
        let ttl = self.config.ttl;
        let mut inner = self.inner.lock().expect("cache mutex poisoned");
        let got = inner.lru.get(key, ttl, now);
        if got.evicted_ttl > 0 {
            self.stats.record_eviction_ttl(got.evicted_ttl);
            self.refresh_residency(&inner);
        }
        match got.hit {
            Some(value) => {
                self.stats.record_hit();
                self.refresh_residency(&inner);
                Some(value)
            }
            None => {
                self.stats.record_miss();
                None
            }
        }
    }

    /// Store a freshly-computed value after a [`try_get`](Self::try_get)
    /// miss (FSD §7.3). Mirrors the store half of
    /// [`get_or_compute`](Self::get_or_compute): inserts and folds any
    /// capacity eviction into stats. Returns the shared `Arc<T>` so the
    /// caller hands back the same instance a concurrent hit would have
    /// seen.
    pub fn store(&self, key: CacheKey, value: T, byte_size: usize) -> Arc<T> {
        let now = Instant::now();
        let value = Arc::new(value);
        let mut inner = self.inner.lock().expect("cache mutex poisoned");
        let out = inner.lru.insert(
            key,
            CacheEntry {
                value: Arc::clone(&value),
                byte_size,
                inserted_at: now,
            },
        );
        if out.evicted_lru > 0 {
            self.stats.record_eviction_lru(out.evicted_lru);
        }
        self.refresh_residency(&inner);
        value
    }

    /// Evict every cached aggregate whose window overlaps the bucket the
    /// write landed in (§7.3). `write_unix_ms` is the timestamp of the
    /// row that changed; the cache computes `bucket_of(write_unix_ms)`
    /// and drops every resident key whose window range contains it.
    /// Returns the number of entries invalidated.
    ///
    /// This is the no-write-through discipline (§7.3): the cache is a
    /// read-only side effect; writes never update entries in place, they
    /// evict the affected window-keys so the next read recomputes.
    pub fn invalidate_write(&self, write_unix_ms: i64) -> u64 {
        let wb = key::bucket_of(write_unix_ms, self.config.invalidation_bucket);
        let mut inner = self.inner.lock().expect("cache mutex poisoned");

        // Scan the resident keys for those whose window range
        // [first_bucket, last_bucket] contains the write bucket (§7.3 /
        // #160-comment-2). O(resident); the cache is bounded so this is
        // cheap, and writes are off the hot read path. No reverse index.
        let victims = inner.lru.keys_overlapping_bucket(wb);
        let mut n = 0u64;
        for k in &victims {
            if inner.lru.remove(k) {
                n += 1;
            }
        }
        self.stats.record_invalidation_write(n);
        self.refresh_residency(&inner);
        n
    }

    /// Drop every entry whose TTL has fired (§7.4). Opportunistic — TTL
    /// is also enforced lazily on read. Returns the count dropped.
    pub fn sweep_expired(&self) -> u64 {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("cache mutex poisoned");
        let drained = inner.lru.evict_expired(self.config.ttl, now);
        let n = drained.len() as u64;
        self.stats.record_eviction_ttl(n);
        self.refresh_residency(&inner);
        n
    }
}

impl<T> Default for Cache<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const HOUR: Duration = Duration::from_secs(3600);
    const HOUR_MS: i64 = 3_600_000;

    fn cfg() -> CacheConfig {
        CacheConfig {
            max_entries: 16,
            max_bytes: 1_000_000,
            ttl: Duration::from_secs(30),
            invalidation_bucket: HOUR,
        }
    }

    /// Build a key whose window is `[start_ms, end_ms]` at 1h buckets.
    fn windowed_key(method: &str, start_ms: i64, end_ms: i64) -> CacheKey {
        CacheKey::new(method, &[7u8; 32], &[0u8; 32], start_ms, end_ms, HOUR)
    }

    #[test]
    fn miss_then_hit() {
        let cache: Cache<i64> = Cache::with_config(cfg());
        let key = windowed_key("agg", 0, HOUR_MS);

        let calls = Cell::new(0);
        let v = cache
            .get_or_compute::<(), _>(key.clone(), || {
                calls.set(calls.get() + 1);
                Ok((100, 8))
            })
            .unwrap();
        assert_eq!(*v, 100);

        // Second call hits — compute closure must NOT run again.
        let v2 = cache
            .get_or_compute::<(), _>(key.clone(), || {
                calls.set(calls.get() + 1);
                Ok((999, 8))
            })
            .unwrap();
        assert_eq!(*v2, 100); // cached value, not 999
        assert_eq!(calls.get(), 1);

        let s = cache.stats();
        assert_eq!(s.hits, 1);
        assert_eq!(s.misses, 1);
        assert_eq!(s.entries_resident, 1);
    }

    #[test]
    fn fail_honest_backend_down_no_stale_serve() {
        // §7.4: a compute error surfaces verbatim; nothing stale served.
        let cache: Cache<i64> = Cache::with_config(cfg());
        let key = windowed_key("agg", 0, HOUR_MS);

        // First call errors (backend unreachable). No entry stored.
        let err: Result<Arc<i64>, &str> =
            cache.get_or_compute(key.clone(), || Err("backend unreachable"));
        assert_eq!(err.unwrap_err(), "backend unreachable");
        assert_eq!(cache.stats().entries_resident, 0);

        // Next call recomputes cleanly — no stale value lingered.
        let v = cache
            .get_or_compute::<&str, _>(key.clone(), || Ok((7, 8)))
            .unwrap();
        assert_eq!(*v, 7);
    }

    #[test]
    fn ttl_expiry_then_backend_down_returns_error_not_stale() {
        // Tightest §7.4 case: a fresh entry exists, TTL fires, then the
        // backend is down on the recompute. The cache must NOT serve the
        // expired value.
        let mut c = cfg();
        c.ttl = Duration::from_millis(1);
        let cache: Cache<i64> = Cache::with_config(c);
        let key = windowed_key("agg", 0, HOUR_MS);

        cache
            .get_or_compute::<&str, _>(key.clone(), || Ok((55, 8)))
            .unwrap();
        // Let the 1ms TTL lapse.
        std::thread::sleep(Duration::from_millis(5));

        let res: Result<Arc<i64>, &str> =
            cache.get_or_compute(key.clone(), || Err("backend down at refresh"));
        assert_eq!(res.unwrap_err(), "backend down at refresh");
        // The expired entry was dropped on the miss; it is NOT resident.
        assert_eq!(cache.stats().entries_resident, 0);
    }

    #[test]
    fn write_invalidates_entry_in_same_bucket() {
        let cache: Cache<i64> = Cache::with_config(cfg());
        // window [0, 1h) lives in bucket 0.
        let key = windowed_key("agg", 0, HOUR_MS - 1);
        cache
            .get_or_compute::<(), _>(key.clone(), || Ok((1, 8)))
            .unwrap();
        assert_eq!(cache.stats().entries_resident, 1);

        // A write at 30 min (bucket 0) invalidates it.
        let n = cache.invalidate_write(HOUR_MS / 2);
        assert_eq!(n, 1);
        assert_eq!(cache.stats().entries_resident, 0);
        assert_eq!(cache.stats().invalidations_write, 1);
    }

    #[test]
    fn write_outside_window_buckets_does_not_invalidate() {
        let cache: Cache<i64> = Cache::with_config(cfg());
        // window in bucket 0.
        let key = windowed_key("agg", 0, HOUR_MS - 1);
        cache
            .get_or_compute::<(), _>(key.clone(), || Ok((1, 8)))
            .unwrap();
        // A write at 5h (bucket 5) is outside the window — no eviction.
        let n = cache.invalidate_write(5 * HOUR_MS);
        assert_eq!(n, 0);
        assert_eq!(cache.stats().entries_resident, 1);
    }

    /// THE CIRISPersist#160 comment-2 correctness case.
    ///
    /// An entry whose window STRADDLES a bucket boundary must be
    /// invalidated by a write that lands in an *earlier* bucket that is
    /// still inside the window — not only by a write in the end-bucket.
    /// An end-bucket-only key (the rejected earlier draft) would miss it.
    #[test]
    fn window_overlap_bucket_invalidation_straddle_160_comment_2() {
        let cache: Cache<i64> = Cache::with_config(cfg());

        // Window [t-7d, t] with t at the start of bucket 200.
        // end = 200h, start = 200h - 168h = 32h. The window overlaps
        // buckets 32..=200 inclusive. bucket_of(end) = 200.
        let end_ms = 200 * HOUR_MS;
        let start_ms = end_ms - 168 * HOUR_MS; // 32h
        let key = windowed_key("repo_stats", start_ms, end_ms);
        cache
            .get_or_compute::<(), _>(key.clone(), || Ok((42, 64)))
            .unwrap();
        assert_eq!(cache.stats().entries_resident, 1);

        // A write at t-1.5h falls in bucket 198 (= bucket_of(198.5h)),
        // which is NOT the end bucket (200) but IS inside the window.
        // The end-bucket-only scheme would MISS this; the overlap-set
        // scheme catches it.
        let write_ms = end_ms - (3 * HOUR_MS) / 2; // 198.5h -> bucket 198
        assert_ne!(
            key::bucket_of(write_ms, HOUR),
            key::bucket_of(end_ms, HOUR),
            "test precondition: write is in a non-end bucket"
        );
        assert!(
            key.overlaps_bucket(key::bucket_of(write_ms, HOUR)),
            "test precondition: write bucket is inside the window's overlap range"
        );

        let n = cache.invalidate_write(write_ms);
        assert_eq!(
            n, 1,
            "mid-window write must invalidate the straddling entry"
        );
        assert_eq!(cache.stats().entries_resident, 0);
    }

    /// CIRISConformance#11 round 2, Finding A — a very wide window must
    /// (a) store + be invalidated by a mid-window write, and (b) NOT OOM.
    ///
    /// The old `CacheKey` carried `Vec<Bucket>` = every overlapped bucket
    /// (a 10-year window at 1h ≈ 87,600 buckets), and the reverse index
    /// inserted a *clone* of that key under each bucket — O(n²) ≈ 61 GB →
    /// SIGKILL. The range-based key holds only `[first, last]`, so this
    /// completes in milliseconds with O(1) per-key memory. We assert the
    /// key materializes no large run (its range is exactly the endpoint
    /// buckets, never an 87k-element Vec) and that invalidation is correct.
    #[test]
    fn wide_window_stores_invalidates_and_does_not_oom() {
        let cache: Cache<i64> = Cache::with_config(cfg());

        // 10-year window at the 1h invalidation bucket: ~87,600 buckets.
        let start_ms: i64 = 0;
        let end_ms: i64 = 10 * 365 * 24 * HOUR_MS;
        let key = windowed_key("repo_stats", start_ms, end_ms);

        // (b) The key holds only the two endpoint buckets — no 87k Vec.
        let (first, last) = key.bucket_range();
        assert_eq!(first, key::bucket_of(start_ms, HOUR));
        assert_eq!(last, key::bucket_of(end_ms, HOUR));
        assert!(
            last - first >= 87_000,
            "precondition: window really does span ~87k buckets"
        );

        // (a) Store completes (no OOM) — this is the SIGKILL path pre-fix.
        cache
            .get_or_compute::<(), _>(key.clone(), || Ok((7, 64)))
            .unwrap();
        assert_eq!(cache.stats().entries_resident, 1);

        // A write 5 years in (a mid-window, non-end bucket) invalidates it.
        let mid_write_ms = 5 * 365 * 24 * HOUR_MS + HOUR_MS / 2;
        let mid_bucket = key::bucket_of(mid_write_ms, HOUR);
        assert_ne!(
            mid_bucket, last,
            "precondition: write is a mid-window, non-end bucket"
        );
        assert!(key.overlaps_bucket(mid_bucket));
        let n = cache.invalidate_write(mid_write_ms);
        assert_eq!(n, 1, "mid-window write must invalidate the wide entry");
        assert_eq!(cache.stats().entries_resident, 0);

        // A write outside the window does NOT invalidate.
        cache
            .get_or_compute::<(), _>(key.clone(), || Ok((7, 64)))
            .unwrap();
        let outside = end_ms + 10 * HOUR_MS;
        assert_eq!(cache.invalidate_write(outside), 0);
        assert_eq!(cache.stats().entries_resident, 1);
    }

    #[test]
    fn lru_eviction_increments_stat_and_evicted_key_not_invalidated() {
        let mut c = cfg();
        c.max_entries = 2;
        let cache: Cache<i64> = Cache::with_config(c);

        // Three distinct windows -> three distinct buckets/keys.
        let k0 = windowed_key("agg", 0, HOUR_MS - 1); // bucket 0
        let k1 = windowed_key("agg", HOUR_MS, 2 * HOUR_MS - 1); // bucket 1
        let k2 = windowed_key("agg", 2 * HOUR_MS, 3 * HOUR_MS - 1); // bucket 2

        cache
            .get_or_compute::<(), _>(k0.clone(), || Ok((0, 8)))
            .unwrap();
        cache
            .get_or_compute::<(), _>(k1.clone(), || Ok((1, 8)))
            .unwrap();
        // Inserting the 3rd evicts the LRU (k0).
        cache
            .get_or_compute::<(), _>(k2.clone(), || Ok((2, 8)))
            .unwrap();

        assert_eq!(cache.stats().evictions_lru, 1);
        assert_eq!(cache.stats().entries_resident, 2);

        // k0 was capacity-evicted, so a write in bucket 0 invalidates
        // nothing — the scan only sees resident keys.
        assert_eq!(cache.invalidate_write(HOUR_MS / 4), 0);
    }

    #[test]
    fn ttl_sweep_drops_expired_and_counts() {
        let mut c = cfg();
        c.ttl = Duration::from_millis(1);
        let cache: Cache<i64> = Cache::with_config(c);
        let key = windowed_key("agg", 0, HOUR_MS - 1);
        cache.get_or_compute::<(), _>(key, || Ok((1, 8))).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let n = cache.sweep_expired();
        assert_eq!(n, 1);
        assert_eq!(cache.stats().entries_resident, 0);
        assert_eq!(cache.stats().evictions_ttl, 1);
    }

    #[test]
    fn scope_disjoint_keys_do_not_share() {
        let cache: Cache<i64> = Cache::with_config(cfg());
        let unauth = key::scope_digest(false, "", &[], &[]);
        let auth = key::scope_digest(true, "id1", &[], &[]);
        let k_unauth = CacheKey::new("agg", &[1u8; 32], &unauth, 0, HOUR_MS, HOUR);
        let k_auth = CacheKey::new("agg", &[1u8; 32], &auth, 0, HOUR_MS, HOUR);

        cache
            .get_or_compute::<(), _>(k_unauth, || Ok((1, 8)))
            .unwrap();
        // Different scope -> miss (separate entry), not a hit.
        let v = cache
            .get_or_compute::<(), _>(k_auth, || Ok((2, 8)))
            .unwrap();
        assert_eq!(*v, 2);
        assert_eq!(cache.stats().misses, 2);
        assert_eq!(cache.stats().hits, 0);
        assert_eq!(cache.stats().entries_resident, 2);
    }

    // ---- tier defaults (§7.2) --------------------------------------

    #[test]
    fn tier_defaults_match_spec() {
        let m = CacheConfig::default_for_tier(DeploymentTier::Mobile);
        assert_eq!(m.max_entries, 256);
        assert_eq!(m.max_bytes, 8 * 1024 * 1024);
        assert_eq!(m.ttl, Duration::from_secs(30));
        assert_eq!(m.invalidation_bucket, Duration::from_secs(3600));

        let e = CacheConfig::default_for_tier(DeploymentTier::Edge);
        assert_eq!(e.max_entries, 512);
        assert_eq!(e.max_bytes, 32 * 1024 * 1024);

        let s = CacheConfig::default_for_tier(DeploymentTier::Server);
        assert_eq!(s.max_entries, 1024);
        assert_eq!(s.max_bytes, 64 * 1024 * 1024);
        assert_eq!(s.ttl, Duration::from_secs(30));
        assert_eq!(s.invalidation_bucket, Duration::from_secs(3600));
    }

    #[test]
    fn default_config_uses_compile_time_tier() {
        let d = CacheConfig::default();
        let t = CacheConfig::default_for_tier(DeploymentTier::compile_time_default());
        assert_eq!(d.max_entries, t.max_entries);
        assert_eq!(d.max_bytes, t.max_bytes);
    }

    #[test]
    fn oversized_value_returned_uncached() {
        // max_bytes smaller than the entry -> insert self-evicts, value
        // still returned honestly, nothing resident.
        let mut c = cfg();
        c.max_bytes = 10;
        let cache: Cache<i64> = Cache::with_config(c);
        let key = windowed_key("agg", 0, HOUR_MS - 1);
        let v = cache
            .get_or_compute::<(), _>(key.clone(), || Ok((123, 1000)))
            .unwrap();
        assert_eq!(*v, 123);
        assert_eq!(cache.stats().entries_resident, 0);
        // The self-evicted entry is not resident, so it invalidates nothing.
        assert_eq!(cache.invalidate_write(0), 0);
    }
}
