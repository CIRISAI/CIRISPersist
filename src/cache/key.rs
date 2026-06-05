//! Cache-key derivation + the §7.3 window-overlap bucket set.
//!
//! FSD V4.0 §7.2 / §7.3. A [`CacheKey`] is derived from
//! `(method_id, filter.cache_key_digest(), scope_digest, time_bucket_SET)`.
//! Two callers with identical `(method, filter, scope, bucket-set)`
//! share a cache entry; two callers with a different scope digest never
//! share (admission resolution differs → answer differs, §7.3
//! scope-disjoint discipline).
//!
//! The correctness fix from CIRISPersist#160 comment 2 lives here: the
//! key carries the **set of buckets the entry's `[window.start,
//! window.end]` overlaps**, not just `bucket_of(window.end)`. A write
//! at timestamp `t` must invalidate every entry whose window *contains*
//! `t`, and a 7-day window keyed only on its end-bucket would miss a
//! write that lands in an earlier bucket but still inside the window.
//!
//! This module deliberately accepts an already-computed `[u8; 32]`
//! filter digest as an opaque input rather than depending on the
//! `Filter` trait (that trait lives in the Commit B/E lane). Key
//! construction takes the filter digest bytes + scope digest bytes +
//! window bounds + bucket duration.

use std::time::Duration;

use sha2::{Digest, Sha256};

/// A federation `federation_keys.key_id`. Key ids are plain strings
/// across the crate (see `src/federation/types.rs`); this alias names
/// the role at the cache surface without inventing a newtype.
pub type KeyId = String;

/// An occurrence-key id — the signing key a caller presents at the
/// boundary (FSD §4.1). Same underlying string shape as [`KeyId`];
/// aliased separately so the [`super::admission::AdmissionCache`]
/// surface reads in the spec's vocabulary.
pub type OccurrenceKeyId = String;

/// An identity-key id — the root identity an occurrence resolves to
/// (FSD §4.1). Used by the admission cache's reverse index.
pub type IdentityKeyId = String;

/// A discrete invalidation bucket — `floor(unix_ms / bucket_ms)`.
///
/// Buckets are the granularity at which a write invalidates cached
/// aggregates (§7.3). A cache entry's window is decomposed into the
/// contiguous run of buckets it overlaps; the reverse index maps each
/// bucket back to the keys whose run contains it.
pub type Bucket = i64;

/// Compute the bucket a unix-ms timestamp falls into for a given
/// bucket duration. `floor` division so negative timestamps (pre-epoch,
/// not expected in practice) still partition monotonically.
pub fn bucket_of(unix_ms: i64, bucket: Duration) -> Bucket {
    let bucket_ms = bucket_ms(bucket);
    unix_ms.div_euclid(bucket_ms)
}

/// Bucket width in milliseconds, clamped to ≥1 so a zero/sub-ms bucket
/// duration can never divide by zero. A 1h default is 3_600_000 ms.
fn bucket_ms(bucket: Duration) -> i64 {
    let ms = bucket.as_millis();
    // Clamp into i64 and to a minimum of 1ms.
    ms.clamp(1, i64::MAX as u128) as i64
}

/// The set of buckets a `[start_unix_ms, end_unix_ms]` window overlaps,
/// inclusive on both ends.
///
/// This is the §7.3 / #160-comment-2 correctness core: a window
/// `[t-7d, t]` overlaps every bucket from `bucket_of(t-7d)` through
/// `bucket_of(t)`. A write anywhere in that closed range invalidates
/// the entry. Returned as a sorted, contiguous, deduplicated `Vec`.
///
/// If `end < start` (degenerate) the range is normalized so the
/// smaller bound leads; an empty window is impossible — a single
/// instant `[t, t]` overlaps exactly one bucket.
pub fn buckets_for_window(start_unix_ms: i64, end_unix_ms: i64, bucket: Duration) -> Vec<Bucket> {
    let (lo, hi) = if start_unix_ms <= end_unix_ms {
        (start_unix_ms, end_unix_ms)
    } else {
        (end_unix_ms, start_unix_ms)
    };
    let first = bucket_of(lo, bucket);
    let last = bucket_of(hi, bucket);
    (first..=last).collect()
}

/// Opaque, content-addressed cache key (FSD §7.2).
///
/// Equality / hashing is over the 32-byte digest of
/// `(method_id, filter_digest, scope_digest)` — the *content* axis. The
/// bucket set is carried alongside (the *time* axis) so the cache can
/// maintain its `bucket → set<CacheKey>` reverse index for §7.3
/// invalidation, but two entries with the same content digest and the
/// same window produce equal keys.
///
/// Note: the window bounds *are* folded into the digest (via the bucket
/// run), so two queries spanning different buckets get distinct keys
/// and bucket-scoped write invalidation stays precise (§7.2).
#[derive(Clone, Debug)]
pub struct CacheKey {
    /// 32-byte content+time digest used for map identity.
    digest: [u8; 32],
    /// The buckets this key's window overlaps, sorted ascending.
    /// Carried so the cache can register/deregister the key in the
    /// reverse index; not all callers need it, hence read via
    /// [`CacheKey::buckets`].
    buckets: Vec<Bucket>,
}

impl CacheKey {
    /// Construct a key from already-computed digests + window bounds.
    ///
    /// - `method_id` — a stable identifier for the read primitive
    ///   (e.g. `"get_repository_statistics:v4.0"`). Namespaces filters
    ///   that happen to hash identically across primitives.
    /// - `filter_digest` — the opaque 32-byte digest the filter type
    ///   produces (`Filter::cache_key_digest`, computed in another
    ///   lane). Treated as an opaque input here.
    /// - `scope_digest` — 32 bytes identifying the caller's resolved
    ///   admission (§7.3 scope-disjoint). Computed by [`scope_digest`].
    /// - `window_start_unix_ms` / `window_end_unix_ms` — the aggregate
    ///   window; decomposed into the overlapping bucket set.
    /// - `bucket` — the substrate's invalidation bucket duration
    ///   (§7.3, default 1h).
    pub fn new(
        method_id: &str,
        filter_digest: &[u8; 32],
        scope_digest: &[u8; 32],
        window_start_unix_ms: i64,
        window_end_unix_ms: i64,
        bucket: Duration,
    ) -> Self {
        let buckets = buckets_for_window(window_start_unix_ms, window_end_unix_ms, bucket);

        let mut h = Sha256::new();
        h.update(b"CacheKey:v4.0\0");
        h.update((method_id.len() as u64).to_le_bytes());
        h.update(method_id.as_bytes());
        h.update(filter_digest);
        h.update(scope_digest);
        // Fold the bucket run into the digest so distinct windows ->
        // distinct keys. We hash the first/last bucket (the run is
        // contiguous) plus the bucket width so equal windows under
        // different bucket settings don't collide.
        let first = buckets.first().copied().unwrap_or(0);
        let last = buckets.last().copied().unwrap_or(0);
        h.update(first.to_le_bytes());
        h.update(last.to_le_bytes());
        h.update((bucket_ms_for_digest(bucket)).to_le_bytes());

        let digest: [u8; 32] = h.finalize().into();
        Self { digest, buckets }
    }

    /// The buckets this key's window overlaps (sorted ascending). The
    /// cache registers the key under each of these in its reverse
    /// index, so a write in any of them invalidates this entry.
    pub fn buckets(&self) -> &[Bucket] {
        &self.buckets
    }

    /// The raw 32-byte digest, exposed for diagnostics / tests.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

fn bucket_ms_for_digest(bucket: Duration) -> i64 {
    bucket_ms(bucket)
}

impl PartialEq for CacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

impl Eq for CacheKey {}

impl std::hash::Hash for CacheKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}

/// Derive the 32-byte scope digest used in [`CacheKey::new`].
///
/// FSD §7.3 scope-disjoint discipline: an Unauthenticated caller and an
/// Authenticated caller — and two Authenticated callers with different
/// admission resolutions — must never share a cache entry. This helper
/// folds the resolved admission set (identity + sorted family +
/// community key ids) into a digest. The cache lane computes this from
/// a `CallerScope`; for THIS commit it takes the resolved components
/// directly so it has no dependency on the scope module.
///
/// `authenticated == false` yields the canonical Unauthenticated
/// digest regardless of the other arguments.
pub fn scope_digest(
    authenticated: bool,
    identity_key_id: &str,
    family_key_ids: &[IdentityKeyId],
    community_key_ids: &[IdentityKeyId],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"CallerScope:v4.0\0");
    if !authenticated {
        h.update([0u8]);
        return h.finalize().into();
    }
    h.update([1u8]);
    h.update((identity_key_id.len() as u64).to_le_bytes());
    h.update(identity_key_id.as_bytes());

    // Sort so set-equal admissions hash identically regardless of the
    // order the resolver returned them.
    let mut fam: Vec<&IdentityKeyId> = family_key_ids.iter().collect();
    fam.sort();
    h.update((fam.len() as u64).to_le_bytes());
    for f in fam {
        h.update((f.len() as u64).to_le_bytes());
        h.update(f.as_bytes());
    }

    let mut com: Vec<&IdentityKeyId> = community_key_ids.iter().collect();
    com.sort();
    h.update((com.len() as u64).to_le_bytes());
    for c in com {
        h.update((c.len() as u64).to_le_bytes());
        h.update(c.as_bytes());
    }

    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);
    const DAY_MS: i64 = 24 * 3600 * 1000;

    #[test]
    fn bucket_of_is_floor() {
        assert_eq!(bucket_of(0, HOUR), 0);
        assert_eq!(bucket_of(3_599_999, HOUR), 0);
        assert_eq!(bucket_of(3_600_000, HOUR), 1);
        assert_eq!(bucket_of(7_200_001, HOUR), 2);
    }

    #[test]
    fn single_instant_window_is_one_bucket() {
        let b = buckets_for_window(3_600_000, 3_600_000, HOUR);
        assert_eq!(b, vec![1]);
    }

    #[test]
    fn seven_day_window_spans_168_hour_buckets() {
        let end = 1000 * 3600 * 1000; // arbitrary, bucket-aligned-ish
        let start = end - 7 * DAY_MS;
        let b = buckets_for_window(start, end, HOUR);
        // inclusive range -> 168 + 1 boundary buckets depending on
        // alignment; assert it is the contiguous run.
        assert_eq!(*b.first().unwrap(), bucket_of(start, HOUR));
        assert_eq!(*b.last().unwrap(), bucket_of(end, HOUR));
        assert_eq!(b.len() as i64, b.last().unwrap() - b.first().unwrap() + 1);
        assert!(b.len() >= 168);
    }

    #[test]
    fn reversed_window_is_normalized() {
        let a = buckets_for_window(10, 7_200_000, HOUR);
        let b = buckets_for_window(7_200_000, 10, HOUR);
        assert_eq!(a, b);
    }

    #[test]
    fn key_equality_is_digest_based() {
        let fd = [1u8; 32];
        let sd = [2u8; 32];
        let k1 = CacheKey::new("m", &fd, &sd, 0, 3_600_000, HOUR);
        let k2 = CacheKey::new("m", &fd, &sd, 0, 3_600_000, HOUR);
        assert_eq!(k1, k2);
        // Different method -> different key.
        let k3 = CacheKey::new("other", &fd, &sd, 0, 3_600_000, HOUR);
        assert_ne!(k1, k3);
        // Different scope -> different key (scope-disjoint).
        let k4 = CacheKey::new("m", &fd, &[9u8; 32], 0, 3_600_000, HOUR);
        assert_ne!(k1, k4);
    }

    #[test]
    fn scope_digest_is_set_order_invariant() {
        let a = scope_digest(
            true,
            "id1",
            &["famA".into(), "famB".into()],
            &["comX".into()],
        );
        let b = scope_digest(
            true,
            "id1",
            &["famB".into(), "famA".into()],
            &["comX".into()],
        );
        assert_eq!(a, b);
        let unauth = scope_digest(false, "id1", &[], &[]);
        assert_ne!(a, unauth);
    }
}
