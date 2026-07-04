//! Consent-decay clock — the time-driven half of the two orthogonal
//! fountain eviction triggers (CIRISPersist#227 residual).
//!
//! The disk-pressure trigger ([`FountainTier::from_pressure`]) drives a
//! `content_id`'s tier down when the HOST is short on bytes. This module
//! is its orthogonal twin: a per-`content_id` **consent clock** that
//! drives the tier down as the content AGES past its consent stream's
//! decay window, **independent of disk pressure** (it fires regardless of
//! free bytes). Both triggers reuse the SAME persist-owned eviction
//! MECHANISM ([`crate::store::Backend::evict_fountain_content_to_tier`]):
//! this module only decides the TARGET tier from elapsed time; it never
//! touches a symbol row itself.
//!
//! # What is spec-pinned vs. an operator-approved default
//!
//! **Spec-pinned** (CIRIS Constitution, `part_4_composition_governance`):
//! - The **TEMPORARY** consent stream has a **14-day** default lifetime
//!   (CC 4.4.3.5.6 — `valid_until = asserted_at + 14d`).
//! - The **ANONYMOUS** / standard "pattern" stream decays over a
//!   **90-day** window (CC 4.4.3.5.1 — the canonical `ciris-agent-90day`
//!   decay protocol: `identity_severed` @0d, `patterns_anonymized` @30d,
//!   `complete` @90d).
//!
//! **Operator-approved DEFAULT (tunable — NOT spec-pinned)**:
//! - The mapping of *elapsed fraction of the window* onto persist's five
//!   [`FountainTier`]s (the [`DECAY_FRACTION_*`](DECAY_FRACTION_T2)
//!   breakpoints). The Constitution's decay-protocol stage map names
//!   consent *stages*, not fountain *keep-counts*; there is no ratified
//!   stage→tier table, so persist interpolates the five tiers evenly
//!   across the window. Change the breakpoints (or the window lengths via
//!   [`TEMPORARY_DECAY_DAYS`] / [`PATTERN_DECAY_DAYS`]) to re-tune.
//! - The **reference instant** the clock measures from is the content's
//!   `admitted_at` (the store's own per-content timestamp). The spec's
//!   TEMPORARY window is measured from `asserted_at` and the ANONYMOUS
//!   decay from the revocation `asserted_at`; persist does not retain
//!   either on the fountain manifest, so `admitted_at` is the honest
//!   substrate-local proxy.
//! - The **class discriminator**: persist reads the content's decay class
//!   from the signed `envelope` (see [`consent_decay_class_from_envelope`]).
//!   Content that declares NO decay class is never touched by the decay
//!   sweep (fail-safe: absent declaration ⇒ retained).

use chrono::{DateTime, Duration, Utc};

use super::eviction::FountainTier;

/// **Spec-pinned** (CC 4.4.3.5.6): the TEMPORARY consent stream's default
/// lifetime, in days. Tunable knob for the decay window of
/// [`ConsentDecayClass::Temporary`].
pub const TEMPORARY_DECAY_DAYS: i64 = 14;

/// **Spec-pinned** (CC 4.4.3.5.1): the ANONYMOUS / standard "pattern"
/// decay window, in days (the canonical `ciris-agent-90day` protocol).
/// Tunable knob for [`ConsentDecayClass::Pattern`].
pub const PATTERN_DECAY_DAYS: i64 = 90;

/// **Default (tunable)** — elapsed-fraction breakpoint at/above which the
/// decay clock targets [`FountainTier::T2`] (drop repair). Below it the
/// content stays [`FountainTier::Full`].
pub const DECAY_FRACTION_T2: f64 = 0.25;
/// **Default (tunable)** — fraction breakpoint for [`FountainTier::T3`].
pub const DECAY_FRACTION_T3: f64 = 0.50;
/// **Default (tunable)** — fraction breakpoint for [`FountainTier::T4`].
pub const DECAY_FRACTION_T4: f64 = 0.75;
/// **Default (tunable)** — fraction breakpoint for [`FountainTier::T5`]
/// (EnvelopeOnly). At/after the full window the content is envelope-only.
pub const DECAY_FRACTION_T5: f64 = 1.0;

/// The consent stream a fountain content unit decays under. Chosen by
/// [`consent_decay_class_from_envelope`] from the content's signed
/// envelope; each class carries a decay window ([`Self::window_days`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDecayClass {
    /// The CIRISAgent TEMPORARY stream — a short 14-day (default) window
    /// (CC 4.4.3.5.6). Content is envelope-only once the window elapses.
    Temporary,
    /// The ANONYMOUS / standard "pattern" stream — the 90-day (default)
    /// decay window (CC 4.4.3.5.1).
    Pattern,
}

impl ConsentDecayClass {
    /// Stable string token (telemetry / logs / envelope round-trip).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ConsentDecayClass::Temporary => "temporary",
            ConsentDecayClass::Pattern => "pattern",
        }
    }

    /// This class's decay window in days (the [`TEMPORARY_DECAY_DAYS`] /
    /// [`PATTERN_DECAY_DAYS`] const). At/after this many days elapsed the
    /// content targets [`FountainTier::T5`] (EnvelopeOnly).
    #[must_use]
    pub fn window_days(self) -> i64 {
        match self {
            ConsentDecayClass::Temporary => TEMPORARY_DECAY_DAYS,
            ConsentDecayClass::Pattern => PATTERN_DECAY_DAYS,
        }
    }

    /// Map `elapsed` (time since the content's reference instant, e.g.
    /// `now - admitted_at`) onto a target [`FountainTier`], mirroring how
    /// [`FountainTier::from_pressure`] maps a `PressureTier`. The five
    /// tiers are laid out evenly across this class's window via the
    /// [`DECAY_FRACTION_*`](DECAY_FRACTION_T2) breakpoints:
    ///
    /// | elapsed / window | Fountain |
    /// |---|---|
    /// | `< 0.25` | `Full`  |
    /// | `< 0.50` | `T2`    |
    /// | `< 0.75` | `T3`    |
    /// | `< 1.00` | `T4`    |
    /// | `>= 1.00`| `T5`    |
    ///
    /// Monotone non-decreasing in `elapsed`, so the clock only ever drives
    /// the tier DOWN (never resurrects symbols). A negative `elapsed`
    /// (clock skew: reference in the future) clamps to `Full`.
    #[must_use]
    pub fn target_tier(self, elapsed: Duration) -> FountainTier {
        let window = self.window_days();
        // Degenerate/tunable-to-zero window ⇒ any non-negative elapsed is
        // fully decayed; a negative elapsed keeps Full.
        if window <= 0 {
            return if elapsed <= Duration::zero() {
                FountainTier::Full
            } else {
                FountainTier::T5
            };
        }
        // Fraction of the window elapsed. Use whole-second precision so
        // the mapping is deterministic and backend-agnostic.
        let elapsed_secs = elapsed.num_seconds();
        if elapsed_secs <= 0 {
            return FountainTier::Full;
        }
        let window_secs = window * 24 * 60 * 60;
        #[allow(clippy::cast_precision_loss)]
        let fraction = elapsed_secs as f64 / window_secs as f64;
        if fraction < DECAY_FRACTION_T2 {
            FountainTier::Full
        } else if fraction < DECAY_FRACTION_T3 {
            FountainTier::T2
        } else if fraction < DECAY_FRACTION_T4 {
            FountainTier::T3
        } else if fraction < DECAY_FRACTION_T5 {
            FountainTier::T4
        } else {
            FountainTier::T5
        }
    }
}

/// Read the [`ConsentDecayClass`] a fountain content unit decays under
/// from its signed `envelope`. Resolution order:
///
/// 1. Explicit `consent_decay_class` string key: `"temporary"` ⇒
///    [`ConsentDecayClass::Temporary`]; `"pattern"` / `"standard"` ⇒
///    [`ConsentDecayClass::Pattern`].
/// 2. Else a `decay_protocol` string key (CC 4.4.3.5.1 — the producer's
///    published decay-protocol name, e.g. `"ciris-agent-90day"`) ⇒
///    [`ConsentDecayClass::Pattern`] (the standard multi-stage window).
/// 3. Else `None` — the content declares no decay class and the decay
///    sweep leaves it alone (fail-safe: absence ⇒ retained). Disk-pressure
///    eviction still applies; only the time-clock opts out.
///
/// Persist does not otherwise interpret the envelope — it round-trips the
/// producer's signed declaration into a decay schedule. Absent / non-object
/// / non-string values yield `None`.
#[must_use]
pub fn consent_decay_class_from_envelope(
    envelope: &serde_json::Value,
) -> Option<ConsentDecayClass> {
    if let Some(cls) = envelope.get("consent_decay_class").and_then(|v| v.as_str()) {
        return match cls {
            "temporary" => Some(ConsentDecayClass::Temporary),
            "pattern" | "standard" => Some(ConsentDecayClass::Pattern),
            _ => None,
        };
    }
    if envelope
        .get("decay_protocol")
        .and_then(|v| v.as_str())
        .is_some()
    {
        return Some(ConsentDecayClass::Pattern);
    }
    None
}

/// Resolve the decay target tier for one content unit: read its class from
/// the `envelope`, then map `now - admitted_at` through
/// [`ConsentDecayClass::target_tier`]. `None` when the content declares no
/// decay class (⇒ the caller does not touch it).
#[must_use]
pub fn consent_decay_target_tier(
    envelope: &serde_json::Value,
    admitted_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Option<FountainTier> {
    let class = consent_decay_class_from_envelope(envelope)?;
    Some(class.target_tier(now - admitted_at))
}

/// One row the consent-decay sweep considers: the manifest coordinates,
/// the signed `envelope` (carries the decay class), and the store's
/// `admitted_at` (the decay reference instant). Symbol-count-agnostic —
/// the sweep asks [`consent_decay_target_tier`] for a target tier and
/// hands it to the shared eviction mechanism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FountainDecayCandidate {
    /// The content's id (`content_manifest.content_id`).
    pub content_id: String,
    /// The corpus kind (`content_manifest.corpus_kind`).
    pub corpus_kind: String,
    /// The signed envelope — the decay-class source.
    pub envelope: serde_json::Value,
    /// The admission wall-clock (the decay reference instant).
    pub admitted_at: DateTime<Utc>,
}

/// What one [`sweep_consent_decay_once`](crate::Engine::sweep_consent_decay_once)
/// pass did. `symbols_evicted` is the total symbol rows the decay clock
/// removed this pass (0 on an idempotent re-run of an already-decayed
/// corpus); the FFI surfaces this scalar to mirror `sweep_evictions_once`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsentDecaySweepReport {
    /// Content units examined (had a manifest this pass).
    pub content_scanned: u64,
    /// Content units that declare a decay class (were clock-evaluated).
    pub content_with_decay_class: u64,
    /// Content units this pass actually evicted at least one symbol from.
    pub content_decayed: u64,
    /// Total symbol rows the decay clock evicted this pass.
    pub symbols_evicted: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn days(n: i64) -> Duration {
        Duration::days(n)
    }

    #[test]
    fn temporary_14day_schedule() {
        let t = ConsentDecayClass::Temporary;
        assert_eq!(t.window_days(), 14);
        // < 25% of 14d (3.5d) ⇒ Full.
        assert_eq!(t.target_tier(days(0)), FountainTier::Full);
        assert_eq!(t.target_tier(days(3)), FountainTier::Full);
        // 25% (3.5d) .. 50% (7d) ⇒ T2.
        assert_eq!(t.target_tier(days(4)), FountainTier::T2);
        // 50% (7d) .. 75% (10.5d) ⇒ T3.
        assert_eq!(t.target_tier(days(8)), FountainTier::T3);
        // 75% (10.5d) .. 100% (14d) ⇒ T4.
        assert_eq!(t.target_tier(days(11)), FountainTier::T4);
        // >= 14d ⇒ T5 (EnvelopeOnly).
        assert_eq!(t.target_tier(days(14)), FountainTier::T5);
        assert_eq!(t.target_tier(days(100)), FountainTier::T5);
    }

    #[test]
    fn pattern_90day_schedule() {
        let p = ConsentDecayClass::Pattern;
        assert_eq!(p.window_days(), 90);
        assert_eq!(p.target_tier(days(0)), FountainTier::Full);
        assert_eq!(p.target_tier(days(22)), FountainTier::Full); // < 22.5d
        assert_eq!(p.target_tier(days(23)), FountainTier::T2); // >= 22.5d
        assert_eq!(p.target_tier(days(46)), FountainTier::T3); // >= 45d
        assert_eq!(p.target_tier(days(68)), FountainTier::T4); // >= 67.5d
        assert_eq!(p.target_tier(days(90)), FountainTier::T5);
        assert_eq!(p.target_tier(days(365)), FountainTier::T5);
    }

    #[test]
    fn monotone_non_decreasing() {
        // The clock only ever drives DOWN (severity non-decreasing).
        let p = ConsentDecayClass::Pattern;
        let mut prev = p.target_tier(days(0));
        for d in 0..=120 {
            let t = p.target_tier(days(d));
            assert!(t >= prev, "tier regressed at day {d}: {t:?} < {prev:?}");
            prev = t;
        }
    }

    #[test]
    fn negative_elapsed_clamps_to_full() {
        assert_eq!(
            ConsentDecayClass::Temporary.target_tier(days(-5)),
            FountainTier::Full
        );
    }

    #[test]
    fn class_from_envelope_explicit() {
        assert_eq!(
            consent_decay_class_from_envelope(
                &serde_json::json!({ "consent_decay_class": "temporary" })
            ),
            Some(ConsentDecayClass::Temporary)
        );
        assert_eq!(
            consent_decay_class_from_envelope(
                &serde_json::json!({ "consent_decay_class": "pattern" })
            ),
            Some(ConsentDecayClass::Pattern)
        );
        assert_eq!(
            consent_decay_class_from_envelope(
                &serde_json::json!({ "consent_decay_class": "standard" })
            ),
            Some(ConsentDecayClass::Pattern)
        );
    }

    #[test]
    fn class_from_envelope_decay_protocol_is_pattern() {
        assert_eq!(
            consent_decay_class_from_envelope(
                &serde_json::json!({ "decay_protocol": "ciris-agent-90day" })
            ),
            Some(ConsentDecayClass::Pattern)
        );
    }

    #[test]
    fn class_from_envelope_absent_is_none() {
        assert_eq!(
            consent_decay_class_from_envelope(&serde_json::json!({ "x": 1 })),
            None
        );
        // Explicit key with an unknown value ⇒ None (fail-safe: retained).
        assert_eq!(
            consent_decay_class_from_envelope(
                &serde_json::json!({ "consent_decay_class": "weird" })
            ),
            None
        );
        assert_eq!(
            consent_decay_class_from_envelope(&serde_json::json!("scalar")),
            None
        );
    }

    #[test]
    fn target_tier_helper_reads_envelope_and_clock() {
        let admitted = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let now = admitted + days(20); // past a 14d TEMPORARY window
        assert_eq!(
            consent_decay_target_tier(
                &serde_json::json!({ "consent_decay_class": "temporary" }),
                admitted,
                now
            ),
            Some(FountainTier::T5)
        );
        // No class ⇒ None (untouched).
        assert_eq!(
            consent_decay_target_tier(&serde_json::json!({}), admitted, now),
            None
        );
    }
}
