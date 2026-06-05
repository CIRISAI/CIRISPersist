//! Admission cache — bounded `build_caller_admission` overhead
//! (FSD V4.0 §7.5, CIRISPersist#160 comment 3).
//!
//! `build_caller_admission(engine, occurrence_key_id)` issues ~3
//! backend reads per call: identity-occurrence lookup, family fan-out,
//! and community fan-out. On consumer hot paths those reads dominate
//! ahead of the substrate aggregate cache. This module caches the
//! resolved [`CallerAdmission`] keyed on `occurrence_key_id` with a
//! 5-minute TTL, invalidated on chain writes.
//!
//! Staleness is acceptable here because the federation chain admits
//! identities / families / communities through consensus protocols —
//! its own write cadence is much slower than the 5-minute default, so
//! the worst-case is a 5-minute latency on a fresh membership admission,
//! well below dashboard / relay budgets.
//!
//! **Fail-honest (§7.4 / §7.5):** a cache miss + backend unreachable
//! returns a real error, never a stale admission. This module never
//! serves a past-TTL entry — TTL is checked on read and the entry is
//! dropped, mirroring [`super::Cache`].
//!
//! ## Cross-commit dependency
//!
//! [`CallerAdmission`] is created by Commit B (`src/scope/admission.rs`),
//! a sibling not yet merged. This module is written against
//! `crate::scope::CallerAdmission` / its `OccurrenceKeyId` /
//! `IdentityKeyId` fields as if they exist; until Commit B lands, this
//! file does not compile (the only unresolved symbols are
//! `crate::scope::CallerAdmission` and the scope module). The rest of
//! the cache crate (`lru`, `key`, `stats`, `mod`) has no scope
//! dependency and compiles standalone.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::key::{IdentityKeyId, OccurrenceKeyId};

// Commit B (src/scope/admission.rs) — the resolved admission set. This
// module stores it; it does not construct it (construction is
// crate-private to the scope module, per FSD §4.2 AV-44). The fields
// read below — `occurrence_key_id`, `identity_key_id` — are the
// pub-for-read fields the FSD §4.1 shape defines.
use crate::scope::CallerAdmission;

/// Default admission-cache TTL (§7.5): 5 minutes.
pub const DEFAULT_ADMISSION_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Default)]
struct AtomicAdmissionStats {
    hits: AtomicU64,
    misses: AtomicU64,
    evictions_ttl: AtomicU64,
    invalidations_chain_write: AtomicU64,
    entries_resident: AtomicU64,
}

impl AtomicAdmissionStats {
    fn snapshot(&self) -> AdmissionStats {
        AdmissionStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions_ttl: self.evictions_ttl.load(Ordering::Relaxed),
            invalidations_chain_write: self.invalidations_chain_write.load(Ordering::Relaxed),
            entries_resident: self.entries_resident.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of admission-cache observability counters (§7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AdmissionStats {
    /// Resolutions served from a live cached admission.
    pub hits: u64,
    /// Resolutions that fell through to the backend
    /// (`build_caller_admission`).
    pub misses: u64,
    /// Entries dropped because their 5-minute TTL fired.
    pub evictions_ttl: u64,
    /// Entries dropped by chain-write invalidation
    /// (`put_identity_occurrence` / `put_family` / `put_community`).
    pub invalidations_chain_write: u64,
    /// Entries currently resident.
    pub entries_resident: u64,
}

struct Slot {
    admission: Arc<CallerAdmission>,
    inserted_at: Instant,
}

impl Slot {
    fn is_expired(&self, ttl: Duration, now: Instant) -> bool {
        now.saturating_duration_since(self.inserted_at) >= ttl
    }
}

struct Inner {
    /// `occurrence_key_id → cached admission`.
    map: HashMap<OccurrenceKeyId, Slot>,
    /// Reverse index `identity_key_id → set<OccurrenceKeyId>` so a
    /// family/community write invalidates every cached admission whose
    /// resolved identity is in the changed member set in O(|members|)
    /// (§7.5).
    by_identity: HashMap<IdentityKeyId, HashSet<OccurrenceKeyId>>,
}

impl Inner {
    fn deregister(&mut self, occurrence_key_id: &str) {
        if let Some(slot) = self.map.remove(occurrence_key_id) {
            let identity = &slot.admission.identity_key_id;
            if let Some(set) = self.by_identity.get_mut(identity) {
                set.remove(occurrence_key_id);
                if set.is_empty() {
                    self.by_identity.remove(identity);
                }
            }
        }
    }
}

/// The admission cache (§7.5). Keyed on `occurrence_key_id`, 5-minute
/// default TTL, chain-write invalidation. Reuses the same fail-honest
/// discipline as [`super::Cache`]: never serve a stale or past-TTL
/// admission.
pub struct AdmissionCache {
    inner: Mutex<Inner>,
    ttl: Duration,
    stats: AtomicAdmissionStats,
}

impl AdmissionCache {
    /// Construct with the §7.5 default 5-minute TTL.
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_ADMISSION_TTL)
    }

    /// Construct with an explicit TTL — operators with tighter
    /// chain-staleness requirements override here (§7.5).
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                by_identity: HashMap::new(),
            }),
            ttl,
            stats: AtomicAdmissionStats::default(),
        }
    }

    /// Observability snapshot (§7.5). Exposed as a public Rust method;
    /// the PyO3 `Engine.admission_cache_stats()` binding is the FFI
    /// commit, not this one.
    pub fn stats(&self) -> AdmissionStats {
        self.stats.snapshot()
    }

    fn refresh_residency(&self, inner: &Inner) {
        self.stats
            .entries_resident
            .store(inner.map.len() as u64, Ordering::Relaxed);
    }

    /// Read-through resolution. Returns a live cached admission or runs
    /// `resolve` (typically `build_caller_admission`), caches its
    /// result, and returns it.
    ///
    /// **Fail-honest (§7.5):** when `resolve` errors — backend
    /// unreachable — the error is returned verbatim and no stale
    /// admission is served. A TTL-expired entry is dropped on the miss
    /// before `resolve` runs.
    pub fn get_or_resolve<E, F>(
        &self,
        occurrence_key_id: &str,
        resolve: F,
    ) -> Result<Arc<CallerAdmission>, E>
    where
        F: FnOnce() -> Result<CallerAdmission, E>,
    {
        let now = Instant::now();

        // Fast path: live hit.
        {
            let mut inner = self.inner.lock().expect("admission cache poisoned");
            let expired = match inner.map.get(occurrence_key_id) {
                Some(slot) => slot.is_expired(self.ttl, now),
                None => false,
            };
            if expired {
                inner.deregister(occurrence_key_id);
                self.stats.evictions_ttl.fetch_add(1, Ordering::Relaxed);
                self.refresh_residency(&inner);
            } else if let Some(slot) = inner.map.get(occurrence_key_id) {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(Arc::clone(&slot.admission));
            }
        }

        // Miss: resolve outside the lock.
        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        let admission = Arc::new(resolve()?); // §7.5 fail-honest: error surfaces

        let mut inner = self.inner.lock().expect("admission cache poisoned");
        // Replace any prior entry (clears its reverse-index slot).
        inner.deregister(occurrence_key_id);
        inner
            .by_identity
            .entry(admission.identity_key_id.clone())
            .or_default()
            .insert(occurrence_key_id.to_string());
        inner.map.insert(
            occurrence_key_id.to_string(),
            Slot {
                admission: Arc::clone(&admission),
                inserted_at: now,
            },
        );
        self.refresh_residency(&inner);
        Ok(admission)
    }

    /// Chain-write invalidation for `put_identity_occurrence(io)` —
    /// invalidate the cached admission for `io.occurrence_key_id`
    /// (§7.5). Returns true if an entry was evicted.
    pub fn invalidate_occurrence(&self, occurrence_key_id: &str) -> bool {
        let mut inner = self.inner.lock().expect("admission cache poisoned");
        let evicted = inner.map.contains_key(occurrence_key_id);
        if evicted {
            inner.deregister(occurrence_key_id);
            self.stats
                .invalidations_chain_write
                .fetch_add(1, Ordering::Relaxed);
            self.refresh_residency(&inner);
        }
        evicted
    }

    /// Chain-write invalidation for `put_family(f)` / `put_community(c)`
    /// — invalidate every cached admission whose resolved
    /// `identity_key_id` is in the changed member set (§7.5). The
    /// `identity_key_id → set<OccurrenceKeyId>` reverse index makes this
    /// O(|members|). Returns the number of entries evicted.
    pub fn invalidate_members<I, S>(&self, member_identity_key_ids: I) -> u64
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut inner = self.inner.lock().expect("admission cache poisoned");
        // Collect victims first (can't mutate while iterating the index).
        let mut victims: HashSet<OccurrenceKeyId> = HashSet::new();
        for identity in member_identity_key_ids {
            if let Some(set) = inner.by_identity.get(identity.as_ref()) {
                for occ in set {
                    victims.insert(occ.clone());
                }
            }
        }
        let mut n = 0u64;
        for occ in &victims {
            if inner.map.contains_key(occ) {
                inner.deregister(occ);
                n += 1;
            }
        }
        if n > 0 {
            self.stats
                .invalidations_chain_write
                .fetch_add(n, Ordering::Relaxed);
            self.refresh_residency(&inner);
        }
        n
    }

    /// Drop every entry whose TTL has fired (§7.5). Opportunistic — TTL
    /// is also enforced lazily on read. Returns the count dropped.
    pub fn sweep_expired(&self) -> u64 {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("admission cache poisoned");
        let expired: Vec<OccurrenceKeyId> = inner
            .map
            .iter()
            .filter(|(_, slot)| slot.is_expired(self.ttl, now))
            .map(|(k, _)| k.clone())
            .collect();
        for k in &expired {
            inner.deregister(k);
        }
        let n = expired.len() as u64;
        if n > 0 {
            self.stats.evictions_ttl.fetch_add(n, Ordering::Relaxed);
            self.refresh_residency(&inner);
        }
        n
    }
}

impl Default for AdmissionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    //! These tests depend on Commit B's `crate::scope::CallerAdmission`
    //! and so only compile once that sibling lands. They are written to
    //! the FSD §4.1 shape: `occurrence_key_id`, `identity_key_id`,
    //! `family_key_ids`, `community_key_ids`.
    use super::*;

    fn admission(occ: &str, identity: &str) -> CallerAdmission {
        // Commit B owns the constructor (crate-private, AV-44). Use the
        // crate-private test builder it exposes. Field shape per FSD §4.1.
        CallerAdmission::for_test(occ, identity, std::iter::empty(), std::iter::empty())
    }

    #[test]
    fn miss_then_hit() {
        let cache = AdmissionCache::new();
        let calls = std::cell::Cell::new(0);
        let a = cache
            .get_or_resolve::<(), _>("occ1", || {
                calls.set(calls.get() + 1);
                Ok(admission("occ1", "id1"))
            })
            .unwrap();
        assert_eq!(a.identity_key_id, "id1");
        let _ = cache
            .get_or_resolve::<(), _>("occ1", || {
                calls.set(calls.get() + 1);
                Ok(admission("occ1", "SHOULD_NOT_RUN"))
            })
            .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(cache.stats().hits, 1);
        assert_eq!(cache.stats().misses, 1);
        assert_eq!(cache.stats().entries_resident, 1);
    }

    #[test]
    fn fail_honest_no_stale() {
        let cache = AdmissionCache::new();
        let e: Result<Arc<CallerAdmission>, &str> =
            cache.get_or_resolve("occ1", || Err("backend down"));
        assert_eq!(e.unwrap_err(), "backend down");
        assert_eq!(cache.stats().entries_resident, 0);
    }

    #[test]
    fn invalidate_occurrence_drops_entry() {
        let cache = AdmissionCache::new();
        cache
            .get_or_resolve::<(), _>("occ1", || Ok(admission("occ1", "id1")))
            .unwrap();
        assert!(cache.invalidate_occurrence("occ1"));
        assert!(!cache.invalidate_occurrence("occ1")); // gone
        assert_eq!(cache.stats().invalidations_chain_write, 1);
        assert_eq!(cache.stats().entries_resident, 0);
    }

    #[test]
    fn invalidate_members_uses_reverse_index() {
        let cache = AdmissionCache::new();
        // Two occurrences of identity id1, one of id2.
        cache
            .get_or_resolve::<(), _>("occA", || Ok(admission("occA", "id1")))
            .unwrap();
        cache
            .get_or_resolve::<(), _>("occB", || Ok(admission("occB", "id1")))
            .unwrap();
        cache
            .get_or_resolve::<(), _>("occC", || Ok(admission("occC", "id2")))
            .unwrap();

        // A put_family touching member id1 invalidates occA + occB only.
        let n = cache.invalidate_members(["id1"]);
        assert_eq!(n, 2);
        assert_eq!(cache.stats().entries_resident, 1); // occC remains
        assert_eq!(cache.stats().invalidations_chain_write, 2);
    }

    #[test]
    fn ttl_expiry_is_miss_not_stale() {
        let cache = AdmissionCache::with_ttl(Duration::from_millis(1));
        cache
            .get_or_resolve::<(), _>("occ1", || Ok(admission("occ1", "id1")))
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        // Past TTL: resolve must run again (no stale serve).
        let ran = std::cell::Cell::new(false);
        cache
            .get_or_resolve::<(), _>("occ1", || {
                ran.set(true);
                Ok(admission("occ1", "id1"))
            })
            .unwrap();
        assert!(ran.get());
        assert_eq!(cache.stats().evictions_ttl, 1);
    }
}
