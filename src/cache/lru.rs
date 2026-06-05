//! Bounded LRU keyed `CacheKey → Arc<CacheEntry>` (FSD V4.0 §7.2/§7.3).
//!
//! Two bounds (`max_entries`, `max_bytes`) and two eviction reasons
//! (LRU/capacity, TTL). The implementation is self-contained — no
//! external `lru` crate — so it is independently testable and the
//! eviction accounting is fully visible to the cache surface that owns
//! the stats counters.
//!
//! Recency is tracked with a monotone access tick rather than an
//! intrusive linked list: every `get`/`insert` stamps the entry with
//! the next tick, and capacity eviction picks the smallest tick. For
//! the cache's working-set sizes (hundreds–thousands of entries) the
//! `O(n)` victim scan is cheaper than maintaining a doubly-linked list
//! under a mutex, and it keeps the structure `#![deny(unsafe_code)]`
//! clean.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::key::CacheKey;

/// A cached value plus the accounting the LRU + TTL eviction need.
///
/// `byte_size` is the caller-declared resident cost (the cache does not
/// introspect `T`); `inserted_at` anchors TTL. The payload is held
/// behind an `Arc` so a hit hands the caller a cheap `Arc<T>` clone
/// without cloning `T`. `T` is the cached payload — for aggregates this
/// is the result struct, but the LRU is generic so the admission cache
/// reuses it.
#[derive(Debug)]
pub struct CacheEntry<T> {
    /// The cached payload, shared so reads clone the `Arc`, not `T`.
    pub value: Arc<T>,
    /// Caller-declared resident byte cost. Summed into the
    /// `bytes_resident` gauge and checked against `max_bytes`.
    pub byte_size: usize,
    /// When the entry was inserted — the TTL anchor.
    pub inserted_at: Instant,
}

impl<T> CacheEntry<T> {
    /// True iff `now - inserted_at >= ttl` — the entry has aged out.
    pub fn is_expired(&self, ttl: Duration, now: Instant) -> bool {
        now.saturating_duration_since(self.inserted_at) >= ttl
    }
}

struct Slot<T> {
    entry: Arc<CacheEntry<T>>,
    /// Recency tick — larger is more-recently used.
    last_tick: u64,
}

/// Outcome of an `insert`, surfacing what the cache surface must fold
/// into its stats counters.
#[derive(Debug, Default, Clone, Copy)]
pub struct InsertOutcome {
    /// Entries dropped by capacity (entries or bytes) eviction.
    pub evicted_lru: u64,
}

/// A bounded LRU map with `max_entries` + `max_bytes` + TTL eviction.
///
/// Not internally synchronized — the owning [`super::Cache`] /
/// [`super::admission::AdmissionCache`] wraps it in a `Mutex`. TTL is
/// checked lazily on `get` (expired entries are reported, not served)
/// and eagerly drained by [`LruCache::evict_expired`].
pub struct LruCache<T> {
    map: HashMap<CacheKey, Slot<T>>,
    max_entries: usize,
    max_bytes: usize,
    bytes_resident: usize,
    tick: u64,
}

impl<T> LruCache<T> {
    /// Construct an empty cache with the given bounds. A `max_entries`
    /// or `max_bytes` of zero makes the cache refuse to retain anything
    /// (every insert immediately evicts itself) — a degenerate but
    /// well-defined configuration.
    pub fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            map: HashMap::new(),
            max_entries,
            max_bytes,
            bytes_resident: 0,
            tick: 0,
        }
    }

    /// Current resident entry count.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True iff no entries are resident.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Approximate resident bytes (sum of entry `byte_size`s).
    pub fn bytes_resident(&self) -> usize {
        self.bytes_resident
    }

    fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    /// Fetch a live (non-expired) entry, bumping its recency. Returns
    /// `None` when the key is absent OR present-but-expired. An expired
    /// entry is **dropped** here (and counted via the returned
    /// [`GetOutcome`]) rather than served — the §7.4 fail-honest rule:
    /// the cache never serves past-TTL data.
    pub fn get(&mut self, key: &CacheKey, ttl: Duration, now: Instant) -> GetOutcome<T> {
        let expired = match self.map.get(key) {
            Some(slot) => slot.entry.is_expired(ttl, now),
            None => {
                return GetOutcome {
                    hit: None,
                    evicted_ttl: 0,
                }
            }
        };
        if expired {
            self.remove_internal(key);
            return GetOutcome {
                hit: None,
                evicted_ttl: 1,
            };
        }
        let tick = self.next_tick();
        let slot = self.map.get_mut(key).expect("present checked above");
        slot.last_tick = tick;
        GetOutcome {
            hit: Some(Arc::clone(&slot.entry.value)),
            evicted_ttl: 0,
        }
    }

    /// Insert (or replace) an entry, evicting by capacity as needed to
    /// stay within both bounds. Returns the number of capacity
    /// evictions so the cache surface can account them.
    pub fn insert(&mut self, key: CacheKey, entry: CacheEntry<T>) -> InsertOutcome {
        let tick = self.next_tick();
        let byte_size = entry.byte_size;

        // Replace semantics: drop the old resident bytes first.
        if let Some(old) = self.map.remove(&key) {
            self.bytes_resident = self.bytes_resident.saturating_sub(old.entry.byte_size);
        }

        self.map.insert(
            key,
            Slot {
                entry: Arc::new(entry),
                last_tick: tick,
            },
        );
        self.bytes_resident = self.bytes_resident.saturating_add(byte_size);

        let mut evicted_lru = 0u64;
        while self.over_capacity() {
            if self.evict_lru_victim().is_some() {
                evicted_lru += 1;
            } else {
                break; // empty — nothing left to evict
            }
        }
        InsertOutcome { evicted_lru }
    }

    fn over_capacity(&self) -> bool {
        self.map.len() > self.max_entries || self.bytes_resident > self.max_bytes
    }

    /// Evict the least-recently-used entry. Returns its key if one was
    /// evicted.
    fn evict_lru_victim(&mut self) -> Option<CacheKey> {
        let victim = self
            .map
            .iter()
            .min_by_key(|(_, slot)| slot.last_tick)
            .map(|(k, _)| k.clone())?;
        self.remove_internal(&victim);
        Some(victim)
    }

    /// Remove a key unconditionally (used by write/chain invalidation).
    /// Returns true if an entry was present.
    pub fn remove(&mut self, key: &CacheKey) -> bool {
        self.remove_internal(key)
    }

    fn remove_internal(&mut self, key: &CacheKey) -> bool {
        if let Some(slot) = self.map.remove(key) {
            self.bytes_resident = self.bytes_resident.saturating_sub(slot.entry.byte_size);
            true
        } else {
            false
        }
    }

    /// Drain every expired entry, returning the keys removed so the
    /// owning cache can deregister them from its reverse index and
    /// count the TTL evictions. Called opportunistically (e.g. before a
    /// write-invalidation sweep) — TTL is also enforced lazily on
    /// `get`.
    pub fn evict_expired(&mut self, ttl: Duration, now: Instant) -> Vec<CacheKey> {
        let expired: Vec<CacheKey> = self
            .map
            .iter()
            .filter(|(_, slot)| slot.entry.is_expired(ttl, now))
            .map(|(k, _)| k.clone())
            .collect();
        for k in &expired {
            self.remove_internal(k);
        }
        expired
    }

    /// True iff the key is resident (regardless of TTL). Test/diagnostic
    /// helper — does not bump recency and does not drop expired entries.
    pub fn contains_resident(&self, key: &CacheKey) -> bool {
        self.map.contains_key(key)
    }
}

/// Outcome of a [`LruCache::get`] — the hit payload (if any) plus
/// whether a TTL eviction happened so the cache surface can count it.
pub struct GetOutcome<T> {
    /// The live payload, or `None` on miss / TTL-expiry.
    pub hit: Option<Arc<T>>,
    /// 1 when a past-TTL entry was dropped during this lookup, else 0.
    pub evicted_ttl: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const TTL: Duration = Duration::from_secs(30);
    const HOUR: Duration = Duration::from_secs(3600);

    fn key(n: u8) -> CacheKey {
        CacheKey::new("m", &[n; 32], &[0u8; 32], 0, 3_600_000, HOUR)
    }

    fn entry(byte_size: usize, now: Instant) -> CacheEntry<u32> {
        CacheEntry {
            value: Arc::new(42),
            byte_size,
            inserted_at: now,
        }
    }

    #[test]
    fn insert_and_get_hits() {
        let now = Instant::now();
        let mut c = LruCache::new(10, 1_000_000);
        c.insert(key(1), entry(10, now));
        let got = c.get(&key(1), TTL, now);
        assert!(got.hit.is_some());
        assert_eq!(*got.hit.unwrap(), 42);
    }

    #[test]
    fn lru_evicts_least_recently_used_on_entry_bound() {
        let now = Instant::now();
        let mut c = LruCache::new(2, 1_000_000);
        c.insert(key(1), entry(10, now));
        c.insert(key(2), entry(10, now));
        // Touch key(1) so key(2) is now the LRU victim.
        assert!(c.get(&key(1), TTL, now).hit.is_some());
        let out = c.insert(key(3), entry(10, now));
        assert_eq!(out.evicted_lru, 1);
        assert!(c.contains_resident(&key(1)));
        assert!(!c.contains_resident(&key(2))); // evicted
        assert!(c.contains_resident(&key(3)));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn byte_bound_evicts() {
        let now = Instant::now();
        let mut c = LruCache::new(100, 100); // 100 bytes max
        c.insert(key(1), entry(60, now));
        let out = c.insert(key(2), entry(60, now)); // 120 > 100
        assert_eq!(out.evicted_lru, 1);
        assert_eq!(c.bytes_resident(), 60);
    }

    #[test]
    fn ttl_expiry_on_get_is_a_miss_not_a_stale_serve() {
        let now = Instant::now();
        let mut c = LruCache::new(10, 1_000_000);
        c.insert(key(1), entry(10, now));
        let later = now + Duration::from_secs(31); // past 30s TTL
        let got = c.get(&key(1), TTL, later);
        assert!(got.hit.is_none()); // never serve stale
        assert_eq!(got.evicted_ttl, 1);
        assert!(!c.contains_resident(&key(1))); // dropped
    }

    #[test]
    fn evict_expired_drains_aged_entries() {
        let now = Instant::now();
        let mut c = LruCache::new(10, 1_000_000);
        c.insert(key(1), entry(10, now));
        c.insert(key(2), entry(10, now + Duration::from_secs(40)));
        let later = now + Duration::from_secs(31);
        let drained = c.evict_expired(TTL, later);
        assert_eq!(drained.len(), 1);
        assert!(drained.contains(&key(1)));
        assert!(c.contains_resident(&key(2))); // inserted later, still live
    }

    #[test]
    fn replace_updates_resident_bytes() {
        let now = Instant::now();
        let mut c = LruCache::new(10, 1_000_000);
        c.insert(key(1), entry(100, now));
        assert_eq!(c.bytes_resident(), 100);
        c.insert(key(1), entry(20, now)); // replace
        assert_eq!(c.bytes_resident(), 20);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn remove_is_unconditional() {
        let now = Instant::now();
        let mut c = LruCache::new(10, 1_000_000);
        c.insert(key(1), entry(10, now));
        assert!(c.remove(&key(1)));
        assert!(!c.remove(&key(1)));
        assert_eq!(c.bytes_resident(), 0);
    }
}
