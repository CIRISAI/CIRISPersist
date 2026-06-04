//! Verify-coordination R1+Q1 substrate constants + merge comparator
//! (CIRISPersist#143; CIRISVerify FEDERATION_THREAT_MODEL §3.3,
//! ratified v1.1, audited v1.2 at 51da15f).
//!
//! # What this module is
//!
//! Two structural-gap closures from the federation threat model land
//! their wire-format-normative constants here:
//!
//! - **R1 — τ_propagate**: how fast a revocation propagates across the
//!   federation under the normal and degraded paths. Drives the
//!   `holds_bytes` directory freshness check (CEG §10.1.2) and the
//!   F-AV-13 cache TTL (revocation cache MUST be ≤ τ_normal/2).
//! - **Q1 — quorum-write**: cross-region write consistency under
//!   bounded staleness, with a deterministic 3-tier merge rule that
//!   tie-breaks competing writes to the same logical state. Closes
//!   F-AV-FRONTRUN (quorum-timestamp ordering) and F-AV-ROLLBACK
//!   (anti-rollback monotonicity at admission, not post-hoc).
//!
//! The constants are wire-format-normative — they appear in receipt
//! payloads, cache-TTL contracts, and the threat-model's deterministic
//! merge rule. Persist owns them as the substrate enforcement floor;
//! consumers (verify-coord workers, regional gossip relays, edge
//! caches) read them rather than redefine them.
//!
//! # Anti-rollback discipline
//!
//! The spec is explicit: anti-rollback is enforced **at admission**,
//! before quorum is asked — a write that would decrease the monotonic
//! counter for a `revoked_key_id` never enters the quorum gate, so a
//! sufficient minority of regions cannot ratify a rollback. The
//! comparator in this module is the determinism floor; the admission
//! check at `put_revocation` is the temporal floor. Both are required.
//!
//! # Why these constants live here and not in CIRISVerify
//!
//! Persist is the substrate that stores `federation_revocations` rows
//! and computes the merge under contention. Verify ships the spec
//! text + the contract; persist enforces the constants in the row
//! lifecycle. Same split as `cohort_scope` (CEG normative; persist
//! enforces admission) and `holds_bytes` suppression (CEG normative;
//! persist enforces `store_blob_local`).

use std::cmp::Ordering;
use std::time::Duration;

/// **R1 — τ_normal.** Maximum propagation deadline for the fresh path
/// (a revocation MUST reach every region within this window under
/// nominal network conditions). Spec value: 60 seconds.
///
/// Drives the F-AV-13 revocation-cache TTL ceiling
/// ([`REVOCATION_CACHE_TTL`]), which is normatively `τ_normal / 2`.
pub const TAU_NORMAL: Duration = Duration::from_secs(60);

/// **R1 — τ_partial.** Maximum propagation deadline for the degraded
/// path (a revocation MUST reach every region within this window under
/// partial connectivity / lossy links). Spec value: 300 seconds.
///
/// Shared with Q1 as [`BOUNDED_STALENESS`] — under the quorum-write
/// contract, a cross-region read MAY observe up to τ_partial of
/// staleness relative to the most-recent regional write.
pub const TAU_PARTIAL: Duration = Duration::from_secs(300);

/// **Q1 — bounded staleness.** Maximum staleness a cross-region
/// reader MAY observe relative to the most-recent regional write
/// before quorum-acknowledgment lands. Equal to [`TAU_PARTIAL`]
/// (300s) by spec.
pub const BOUNDED_STALENESS: Duration = TAU_PARTIAL;

/// **Q1 — N (region count).** Number of regions participating in
/// the quorum-write contract. Spec value: 3 (`us` / `eu` / `apac`).
///
/// Pinned at 3 in v1.1; spec changes to N would be a wire-format
/// version bump (different quorum threshold ratio).
pub const N_REGIONS: usize = 3;

/// **Q1 — quorum write threshold.** Minimum regional acknowledgments
/// for a revocation to be considered quorum-committed. Computed as
/// `⌈2N/3⌉ = 2` for N=3.
pub const QUORUM_WRITE_THRESHOLD: usize = 2;

/// **F-AV-13 — revocation cache TTL.** Maximum age of a cached
/// revocation-state entry before it MUST be re-read. Normatively
/// `τ_normal / 2 = 30s` so a fresh-path propagation always overtakes
/// the cache by a safety margin.
pub const REVOCATION_CACHE_TTL: Duration = Duration::from_secs(30);

/// Q1 region closed-set vocabulary
/// (CIRISVerify FEDERATION_THREAT_MODEL §3.3.2).
///
/// The substrate admits a revocation row's `observed_region` only
/// from this closed set; producers asserting anything else are
/// rejected at admission. Same closed-set discipline as
/// [`crate::federation::types::cohort_scope`].
pub mod region {
    /// North-American region.
    pub const US: &str = "us";
    /// European region.
    pub const EU: &str = "eu";
    /// Asia-Pacific region.
    pub const APAC: &str = "apac";

    /// True iff `s` is one of the three closed-set region values.
    pub fn is_valid(s: &str) -> bool {
        matches!(s, US | EU | APAC)
    }

    /// All three regions in spec-canonical order (`us`, `eu`, `apac`).
    /// Used by the per-region observation tracker.
    pub const ALL: [&str; 3] = [US, EU, APAC];
}

/// One revocation's contribution to the 3-tier deterministic merge.
///
/// Holds the three fields the merge comparator reads — surfaced as a
/// dedicated struct so a consumer can score-rank competing
/// revocations without materializing the full
/// [`crate::federation::Revocation`] row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeBallot<'a> {
    /// Q1 tier-1 — quorum weight (number of regions that have
    /// observed this revocation; 1..=[`N_REGIONS`]).
    pub quorum_weight: u8,
    /// Q1 tier-2 — signed timestamp from the revocation's signed
    /// envelope (the `scrub_timestamp` on the
    /// [`crate::federation::Revocation`] row, exposed as the
    /// spec's `signed_timestamp` mapping).
    pub signed_timestamp: chrono::DateTime<chrono::Utc>,
    /// Q1 tier-3 — `original_content_hash` (hex SHA-256 of the
    /// canonical revocation envelope). Used only as a deterministic
    /// tie-break when tiers 1+2 are exactly equal — exceptional path.
    pub canonical_bytes_hash: &'a str,
}

/// Q1 deterministic 3-tier merge comparator
/// (CIRISVerify FEDERATION_THREAT_MODEL §3.3.2, v1.1 ratified, v1.2
/// audited).
///
/// Returns the [`Ordering`] under which `a` sorts relative to `b` in
/// "winning order" — i.e. [`Ordering::Less`] means **a wins**, in
/// keeping with `slice::sort_by(cmp)` returning the smaller element
/// first.
///
/// Tier hierarchy (each tier is the tie-break for the previous):
///
/// 1. **Higher [`quorum_weight`](MergeBallot::quorum_weight) wins**
///    — a revocation acknowledged by more regions is more
///    authoritative. Encodes the "majority-quorum dominance" rule.
/// 2. **Later [`signed_timestamp`](MergeBallot::signed_timestamp)
///    wins** — anti-rollback monotonic. F-AV-FRONTRUN closure: a
///    racing writer can't undercut a later legitimate revocation by
///    backdating.
/// 3. **Lower [`canonical_bytes_hash`](MergeBallot::canonical_bytes_hash)
///    wins** — pure deterministic tie-break (rare; only triggers
///    when both prior tiers tie exactly). Lex-ascending so two peers
///    with the same inputs converge on the same winner without any
///    coordination round-trip.
///
/// # Determinism contract
///
/// For every pair `(a, b)`, `compare_for_merge(a, b)` and
/// `compare_for_merge(b, a)` are exact opposites — the comparator is
/// a strict total order (no `Equal` outcome unless `a` and `b` are
/// bytewise-identical on all three tiers, in which case the merge
/// has nothing to decide). This is the property the federation relies
/// on for cross-region convergence without coordination.
pub fn compare_for_merge(a: &MergeBallot<'_>, b: &MergeBallot<'_>) -> Ordering {
    // Tier 1: quorum_weight DESC. b.cmp(&a) instead of a.cmp(&b) so
    // a higher weight sorts as "Less" (a wins).
    b.quorum_weight
        .cmp(&a.quorum_weight)
        // Tier 2: signed_timestamp DESC. Later timestamp wins.
        .then_with(|| b.signed_timestamp.cmp(&a.signed_timestamp))
        // Tier 3: canonical_bytes_hash ASC. Lex-lower wins (rare
        // tie-break; pure determinism).
        .then_with(|| a.canonical_bytes_hash.cmp(b.canonical_bytes_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ballot<'a>(weight: u8, ts: &str, hash: &'a str) -> MergeBallot<'a> {
        MergeBallot {
            quorum_weight: weight,
            signed_timestamp: chrono::DateTime::parse_from_rfc3339(ts)
                .unwrap()
                .with_timezone(&chrono::Utc),
            canonical_bytes_hash: hash,
        }
    }

    #[test]
    fn constants_match_v1_1_spec() {
        // Pin the spec values; a drift here means the threat-model
        // spec changed and consumers MUST be updated in lockstep.
        assert_eq!(TAU_NORMAL, Duration::from_secs(60));
        assert_eq!(TAU_PARTIAL, Duration::from_secs(300));
        assert_eq!(BOUNDED_STALENESS, TAU_PARTIAL);
        assert_eq!(N_REGIONS, 3);
        assert_eq!(QUORUM_WRITE_THRESHOLD, 2);
        // F-AV-13: cache TTL is exactly τ_normal/2.
        assert_eq!(REVOCATION_CACHE_TTL * 2, TAU_NORMAL);
    }

    #[test]
    fn region_closed_set_admits_only_three() {
        assert!(region::is_valid("us"));
        assert!(region::is_valid("eu"));
        assert!(region::is_valid("apac"));
        // Common evasions:
        assert!(!region::is_valid("US"));
        assert!(!region::is_valid("global"));
        assert!(!region::is_valid(""));
        assert!(!region::is_valid("us-east-1"));
        assert_eq!(region::ALL, ["us", "eu", "apac"]);
    }

    #[test]
    fn tier1_higher_quorum_weight_wins() {
        // Same timestamp + hash; only weight differs.
        let high = ballot(3, "2026-06-03T12:00:00Z", "aaaa");
        let low = ballot(1, "2026-06-03T12:00:00Z", "aaaa");
        assert_eq!(compare_for_merge(&high, &low), Ordering::Less);
        assert_eq!(compare_for_merge(&low, &high), Ordering::Greater);
    }

    #[test]
    fn tier2_later_signed_timestamp_wins_when_tier1_ties() {
        // Equal weight; later timestamp must win (F-AV-FRONTRUN /
        // anti-rollback monotonic).
        let late = ballot(2, "2026-06-03T12:00:30Z", "aaaa");
        let early = ballot(2, "2026-06-03T12:00:00Z", "aaaa");
        assert_eq!(compare_for_merge(&late, &early), Ordering::Less);
        assert_eq!(compare_for_merge(&early, &late), Ordering::Greater);
    }

    #[test]
    fn tier3_lex_lower_hash_wins_when_tiers_1_and_2_tie() {
        // Pure deterministic tie-break.
        let lo = ballot(2, "2026-06-03T12:00:00Z", "0000");
        let hi = ballot(2, "2026-06-03T12:00:00Z", "ffff");
        assert_eq!(compare_for_merge(&lo, &hi), Ordering::Less);
        assert_eq!(compare_for_merge(&hi, &lo), Ordering::Greater);
    }

    #[test]
    fn tier1_dominates_tier2_and_tier3() {
        // Lower weight but later timestamp + lex-lower hash MUST
        // still lose — quorum dominance is absolute.
        let weak_recent = ballot(1, "2026-06-03T13:00:00Z", "0000");
        let strong_old = ballot(3, "2026-06-03T12:00:00Z", "ffff");
        assert_eq!(compare_for_merge(&strong_old, &weak_recent), Ordering::Less);
    }

    #[test]
    fn tier2_dominates_tier3() {
        // Equal weight, later timestamp wins over lex-lower hash.
        let recent_high = ballot(2, "2026-06-03T13:00:00Z", "ffff");
        let old_low = ballot(2, "2026-06-03T12:00:00Z", "0000");
        assert_eq!(compare_for_merge(&recent_high, &old_low), Ordering::Less);
    }

    #[test]
    fn comparator_is_antisymmetric() {
        // For every (a, b), cmp(a,b) and cmp(b,a) MUST be exact
        // opposites — the determinism contract the federation relies
        // on for cross-region convergence.
        let cases = [
            (
                ballot(3, "2026-06-03T12:00:00Z", "aaaa"),
                ballot(1, "2026-06-03T12:00:00Z", "aaaa"),
            ),
            (
                ballot(2, "2026-06-03T13:00:00Z", "aaaa"),
                ballot(2, "2026-06-03T12:00:00Z", "aaaa"),
            ),
            (
                ballot(2, "2026-06-03T12:00:00Z", "0000"),
                ballot(2, "2026-06-03T12:00:00Z", "ffff"),
            ),
            (
                ballot(1, "2026-06-03T13:00:00Z", "0000"),
                ballot(3, "2026-06-03T12:00:00Z", "ffff"),
            ),
        ];
        for (a, b) in &cases {
            let ab = compare_for_merge(a, b);
            let ba = compare_for_merge(b, a);
            assert_eq!(ab, ba.reverse(), "antisymmetry: {a:?} vs {b:?}");
        }
    }

    #[test]
    fn identical_ballots_compare_equal() {
        let x = ballot(2, "2026-06-03T12:00:00Z", "aaaa");
        let y = ballot(2, "2026-06-03T12:00:00Z", "aaaa");
        assert_eq!(compare_for_merge(&x, &y), Ordering::Equal);
    }
}
