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
//! # Infrastructure does not vote
//!
//! Nothing in this module is an authorization decision. Regions are
//! **replicas**, not voters — a region "acknowledging" a write means it
//! *durably stored* the row, never that it *approved* the content. The
//! "quorum" here is a **replication/durability consistency floor** (CAP:
//! how many replicas must hold a write before it is client-visible) and a
//! **deterministic CRDT merge tie-break** (which of two replicated copies
//! of the *same* logical revocation wins convergence). Both are
//! infrastructure mechanics.
//!
//! *Authorization* — whether a revocation is legitimate at all — is
//! **signature verification against accord/steward keys** (agency), done
//! upstream and never here. A Byzantine region cannot forge a signed
//! revocation; it can only withhold one (an availability fault the
//! signature layer is orthogonal to). So this module MUST NOT reuse the
//! trust-root M-of-N *signature* quorum primitive
//! (`ciris_verify_core::threshold::QuorumPolicy`): coupling a replication
//! ack-count to a governance vote is exactly the `infra:* ≠ agency:*`
//! conflation the constitution forbids (CIRISVerify#77).
//!
//! # Anti-rollback discipline
//!
//! The spec is explicit: anti-rollback is enforced **at admission**,
//! before replication is asked — a write that would decrease the
//! monotonic counter for a `revoked_key_id` never enters the replication
//! path, so no number of regions replicating a stale write can force a
//! rollback into acceptance (regions replicate; they do not adjudicate).
//! The comparator in this module is the determinism floor; the admission
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

/// **Q1 — N (region count).** Number of regions participating in the
/// quorum-write contract, **derived** from [`region::ALL`] — the single
/// source of truth. Currently 3 (`us` / `eu` / `apac`); the region set is
/// **growable** (e.g. `jp` / `uk` / `et`), and N + the write threshold
/// re-derive automatically when a region is added to that list. Adding a
/// region is still a wire-format version bump (the closed admission
/// vocabulary changes), but requires no other edit in this module.
pub const N_REGIONS: usize = region::ALL.len();

/// **Q1 — write-durability quorum (replication ack-count, NOT a vote).**
/// Minimum number of regional **replicas** that must durably hold a
/// revocation before it is treated as quorum-committed / client-visible.
/// This is a CAP consistency floor — a replication acknowledgment count,
/// like a Dynamo/Raft write quorum — **not** an authorization decision
/// (see the module's "Infrastructure does not vote" note; authorization is
/// signature verification upstream).
///
/// Derived from N as the §3.3.2 `⌈2N/3⌉` durability ratio (at N=3 → 2), so
/// it re-derives as the region set grows. It is deliberately NOT wired to
/// the trust-root `QuorumPolicy` signature primitive — that governs agency,
/// this governs replica durability.
///
/// NB currently **reported, not enforced**: the only reader is
/// `verify_coord_constants_json()` (the substrate publishes the CAP
/// contract); row-lifecycle enforcement is tracked at CIRISPersist#143.
pub const QUORUM_WRITE_THRESHOLD: usize = (2 * N_REGIONS).div_ceil(3);

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
///
/// The set is **closed at any given wire version but not hard-limited to
/// three** — it grows as the federation adds regions (`jp` / `uk` / `et` /
/// …). [`ALL`] is the single source of truth: [`is_valid`], [`N_REGIONS`],
/// and [`QUORUM_WRITE_THRESHOLD`] all derive from it, so onboarding a region
/// is a one-line addition here (plus its wire-format version bump).
pub mod region {
    /// North-American region.
    pub const US: &str = "us";
    /// European region.
    pub const EU: &str = "eu";
    /// Asia-Pacific region.
    pub const APAC: &str = "apac";

    /// All federation regions in spec-canonical order. **The single source of
    /// truth** for the closed admission vocabulary and, via [`slice::len`], for
    /// [`super::N_REGIONS`] / [`super::QUORUM_WRITE_THRESHOLD`]. Add a region
    /// here (e.g. `JP` / `UK` / `ET`) to grow N — the write quorum re-derives
    /// as `⌈2N/3⌉`.
    pub const ALL: &[&str] = &[US, EU, APAC];

    /// True iff `s` is one of the closed-set region values (derived from
    /// [`ALL`], never a duplicated match arm).
    #[must_use]
    pub fn is_valid(s: &str) -> bool {
        ALL.contains(&s)
    }
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
///    — a copy of the revocation held by more region replicas wins
///    convergence (more independent replicas observed it). A CRDT
///    merge-dominance rule for deterministic reconciliation — NOT a
///    vote on the revocation's validity (that is settled by signatures
///    upstream; see the module "Infrastructure does not vote" note).
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
        // Current region set is the canonical three; N + threshold DERIVE
        // from region::ALL (not hardcoded), so these track the list.
        assert_eq!(N_REGIONS, 3);
        assert_eq!(N_REGIONS, region::ALL.len());
        assert_eq!(QUORUM_WRITE_THRESHOLD, 2);
        // F-AV-13: cache TTL is exactly τ_normal/2.
        assert_eq!(REVOCATION_CACHE_TTL * 2, TAU_NORMAL);
    }

    #[test]
    fn write_durability_quorum_is_derived_and_grows() {
        // The write-durability quorum is the §3.3.2 replication ratio ⌈2N/3⌉
        // — derived from N, not a literal — and re-derives as the region set
        // grows. This is a replica ack-count, NOT a governance vote, so it is
        // deliberately not routed through the trust-root QuorumPolicy.
        for (n, want) in [(3, 2), (4, 3), (5, 4), (6, 4), (7, 5), (9, 6)] {
            let n: usize = n;
            assert_eq!((2 * n).div_ceil(3), want, "⌈2·{n}/3⌉");
        }
        // The live constant is exactly the formula applied to the live N.
        assert_eq!(QUORUM_WRITE_THRESHOLD, (2 * N_REGIONS).div_ceil(3));
    }

    #[test]
    fn region_closed_set_admits_only_listed() {
        // Every listed region validates; the check derives from region::ALL,
        // so growing the list (jp/uk/et/…) needs no edit here.
        for r in region::ALL {
            assert!(region::is_valid(r), "listed region {r} must validate");
        }
        assert!(region::ALL.starts_with(&["us", "eu", "apac"]));
        // Common evasions stay rejected:
        assert!(!region::is_valid("US"));
        assert!(!region::is_valid("global"));
        assert!(!region::is_valid(""));
        assert!(!region::is_valid("us-east-1"));
        assert!(!region::is_valid("jp")); // not yet onboarded
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
