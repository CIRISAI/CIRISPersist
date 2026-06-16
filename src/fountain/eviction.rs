//! Tier × priority eviction policy (CIRISPersist#227).
//!
//! persist-owned, single ORDER BY: within a `content_id`, evict by
//! `retention_priority DESC` (highest-priority-value first — repair +
//! high-SVC-layer symbols) down to a per-tier keep-count. The manifest
//! is NEVER evicted; only `content_symbols` rows are.
//!
//! Two orthogonal triggers drive the tier down:
//!   1. **DiskPressure** (#149) — the free-bytes [`PressureTier`] maps to
//!      a [`FountainTier`] via [`FountainTier::from_pressure`].
//!   2. **Consent decay** — the Consensual-Evolution clock (TEMPORARY
//!      14-day, 90-day pattern decay) drives the tier down on a consent
//!      schedule independent of disk. **NOTE (follow-on):** this cut
//!      exposes the eviction MECHANISM as a callable
//!      ([`crate::store::Backend::evict_fountain_content_to_tier`]); the
//!      FULL Consensual-Evolution stream scheduling integration (per-
//!      content_id consent clock → tier) is an explicit documented
//!      follow-on and is intentionally NOT built here.

use crate::federation::replication::disk_pressure::PressureTier;

use super::types::FountainManifestV1;

/// The five fountain eviction tiers (CIRISPersist#227 keep-count table).
/// Severity order: `Full < T2 < T3 < T4 < T5` (tighter = more evicted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FountainTier {
    /// Keep `n_source + k_repair` — lossless + FEC headroom.
    Full,
    /// Keep `n_source` (drop repair) — lossless.
    T2,
    /// Keep `[min_viable, n_source)` — partial.
    T3,
    /// Keep `min_viable` — summary-shaped fragments.
    T4,
    /// Keep `0` — EnvelopeOnly (manifest always stays).
    T5,
}

impl FountainTier {
    /// Stable string-token (telemetry / logs).
    pub fn label(&self) -> &'static str {
        match self {
            FountainTier::Full => "full",
            FountainTier::T2 => "t2",
            FountainTier::T3 => "t3",
            FountainTier::T4 => "t4",
            FountainTier::T5 => "t5",
        }
    }

    /// Map a #149 [`PressureTier`] to the fountain eviction tier
    /// (CIRISPersist#227 disk-pressure trigger):
    ///
    /// | DiskPressure | Fountain | Keep |
    /// |---|---|---|
    /// | `Normal`     | `Full` | `n_source + k_repair` |
    /// | `Warn`       | `T2`   | `n_source` (drop repair) |
    /// | `Crit`       | `T3`   | `[min_viable, n_source)` |
    /// | `Stop`       | `T4`   | `min_viable` |
    /// | `HostAtRisk` | `T5`   | `0` (EnvelopeOnly) |
    pub fn from_pressure(tier: PressureTier) -> FountainTier {
        match tier {
            PressureTier::Normal => FountainTier::Full,
            PressureTier::Warn => FountainTier::T2,
            PressureTier::Crit => FountainTier::T3,
            PressureTier::Stop => FountainTier::T4,
            PressureTier::HostAtRisk => FountainTier::T5,
        }
    }

    /// Keep-count for this tier given a manifest's RaptorQ params.
    ///
    /// Clamped so the contract's invariants always hold even on odd
    /// inputs: `min_viable` is clamped to `[0, n_source]`, and `T3`
    /// keeps the midpoint of the `[min_viable, n_source)` band (an
    /// interior partial). The keep-count never exceeds `total`.
    pub fn keep_count(&self, manifest: &FountainManifestV1) -> u64 {
        let n_source = u64::from(manifest.n_source);
        let total = manifest.total_symbols(); // n_source + k_repair
        let min_viable = u64::from(manifest.min_viable_symbols).min(n_source);
        match self {
            FountainTier::Full => total,
            FountainTier::T2 => n_source,
            // T3 lands strictly inside [min_viable, n_source) when that
            // band is non-empty — the partial target. If min_viable ==
            // n_source the band is empty and we keep min_viable.
            FountainTier::T3 => {
                if n_source > min_viable {
                    // Midpoint, biased toward keeping more (ceil),
                    // guaranteed < n_source and >= min_viable.
                    let mid = min_viable + (n_source - min_viable).div_ceil(2);
                    mid.min(n_source.saturating_sub(1)).max(min_viable)
                } else {
                    min_viable
                }
            }
            FountainTier::T4 => min_viable,
            FountainTier::T5 => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fountain::types::MANIFEST_VERSION_V1;

    fn manifest(n_source: u32, k_repair: u32, min_viable: u32) -> FountainManifestV1 {
        FountainManifestV1 {
            content_id: "c".into(),
            corpus_kind: "trace".into(),
            manifest_version: MANIFEST_VERSION_V1,
            n_source,
            k_repair,
            symbol_size: 8,
            original_content_length: 1,
            min_viable_symbols: min_viable,
            symbol_hashes: Vec::new(),
            envelope: serde_json::Value::Null,
            signature: String::new(),
            signature_ml_dsa_65: String::new(),
            pqc_key_id: String::new(),
        }
    }

    #[test]
    fn pressure_maps_to_fountain_tier() {
        assert_eq!(
            FountainTier::from_pressure(PressureTier::Normal),
            FountainTier::Full
        );
        assert_eq!(
            FountainTier::from_pressure(PressureTier::Warn),
            FountainTier::T2
        );
        assert_eq!(
            FountainTier::from_pressure(PressureTier::Crit),
            FountainTier::T3
        );
        assert_eq!(
            FountainTier::from_pressure(PressureTier::Stop),
            FountainTier::T4
        );
        assert_eq!(
            FountainTier::from_pressure(PressureTier::HostAtRisk),
            FountainTier::T5
        );
    }

    #[test]
    fn keep_counts_follow_the_contract_table() {
        // n_source = 10, k_repair = 4, min_viable = 3 → total = 14.
        let m = manifest(10, 4, 3);
        assert_eq!(FountainTier::Full.keep_count(&m), 14, "full keeps N+K");
        assert_eq!(FountainTier::T2.keep_count(&m), 10, "T2 keeps n_source");
        let t3 = FountainTier::T3.keep_count(&m);
        assert!(
            (3..10).contains(&t3),
            "T3 keeps a partial in [min_viable, n_source): {t3}"
        );
        assert_eq!(FountainTier::T4.keep_count(&m), 3, "T4 keeps min_viable");
        assert_eq!(FountainTier::T5.keep_count(&m), 0, "T5 keeps nothing");
    }

    #[test]
    fn keep_count_clamps_min_viable_above_n_source() {
        // min_viable > n_source is nonsense input; clamp to n_source so
        // T4 never asks to keep more than the source set.
        let m = manifest(5, 2, 99);
        assert_eq!(FountainTier::T4.keep_count(&m), 5);
        // T3 band is empty (min_viable clamped == n_source) → keep
        // min_viable (== n_source).
        assert_eq!(FountainTier::T3.keep_count(&m), 5);
    }

    #[test]
    fn tier_ordering_is_severity() {
        assert!(FountainTier::Full < FountainTier::T2);
        assert!(FountainTier::T2 < FountainTier::T3);
        assert!(FountainTier::T3 < FountainTier::T4);
        assert!(FountainTier::T4 < FountainTier::T5);
    }
}
