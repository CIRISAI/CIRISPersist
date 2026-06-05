//! The [`Aggregate`] trait (FSD §6.1) — the fail-honest invariants every
//! aggregate result carries.
//!
//! Landed in the Commit G cut (`get_repository_statistics`, #159) — the
//! first aggregate primitive routed through the substrate cache (§7) and
//! the §4.3 scope gate. Every aggregate result type implements this so a
//! consumer can read `sample_count` (AV-43 k-anonymity hint), the
//! `evaluated_at_unix_ms` (when the answer was computed), and `cache_hit`
//! (whether it came from cache) uniformly.
//!
//! MISSION.md §1.6 — fail honest: small-N is *labelled*, never hidden;
//! staleness is *labelled*, never silently served (§7.4).

/// Invariants every aggregate result carries (FSD §6.1).
///
/// The three accessors below are the substrate's honesty contract:
///
/// - [`Aggregate::sample_count`] — the *top-level* denominator: the
///   number of rows in the scope-filtered windowed set the aggregate
///   answers about. Nested sub-aggregates carry their *own*
///   `sample_count` for the sub-population that contributed to that
///   statistic (FSD §6.3); the two are deliberately distinct.
/// - [`Aggregate::evaluated_at_unix_ms`] — unix-ms the answer was
///   computed against the backend. With `cache_hit == true` this is the
///   *cached* evaluation time, NOT the current time.
/// - [`Aggregate::cache_hit`] — `true` iff served from cache.
pub trait Aggregate {
    /// Top-level sample count — rows in the scope-filtered windowed set
    /// (FSD §6.1). NOT necessarily the count contributing to every
    /// nested sub-aggregate (§6.3). Never elided; zero is honest
    /// (AV-43).
    fn sample_count(&self) -> i64;

    /// Unix milliseconds the aggregate was computed against the backend.
    /// With `cache_hit == true`, the cached evaluation time.
    fn evaluated_at_unix_ms(&self) -> i64;

    /// `true` iff this result came from the cache; `false` = fresh DB
    /// read.
    fn cache_hit(&self) -> bool;
}
