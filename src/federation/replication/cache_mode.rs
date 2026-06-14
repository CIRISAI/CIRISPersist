//! Operator-facing cache-size knob (v6.8.0, CIRISPersist#148).
//!
//! The eviction sweeper + storage budget already exist
//! ([`ReplicationConfig::storage_budget_bytes`] +
//! [`crate::federation::EvictionSweeper`]); the gap this module closes
//! is *operator UX*. Instead of constructing a [`ReplicationConfig`]
//! by hand and calling setters, an operator picks one of three preset
//! [`CacheMode`]s and (optionally) a human-readable byte cap; the
//! preset maps deterministically onto the underlying knobs.
//!
//! # Resolution order (issue #148 §3)
//!
//! `constructor kwarg > env var > mode default`. The env-var layer is
//! [`CacheMode::from_env`]; the kwarg layer is the PyO3 constructor
//! (`cache_mode=` / `max_cache_bytes=`). Both ultimately call
//! [`CacheMode::apply_to`] to fold the preset onto a base
//! [`ReplicationConfig`].
//!
//! # Mission alignment
//!
//! Persist exposes the substrate; consumers compose policy. The three
//! modes are *presets over the same primitive* — power users still
//! reach the raw knobs via
//! [`crate::Engine::with_replication_config`]. We do NOT expose every
//! `ReplicationConfig` field as an env var (issue #148 anti-recs).

use std::time::Duration;

use super::ReplicationConfig;

/// 1 mebibyte (IEC).
pub const MIB: u64 = 1024 * 1024;
/// 1 gibibyte (IEC).
pub const GIB: u64 = 1024 * 1024 * 1024;

/// Default Proxy cap — 100 MiB (mobile / embedded relay).
pub const PROXY_DEFAULT_CACHE_BYTES: u64 = 100 * MIB;
/// Default Proxy TTL — 60 s (aggressive eviction).
pub const PROXY_DEFAULT_TTL_SECONDS: u32 = 60;
/// Default Cache cap — 10 GiB (standard server / desktop).
pub const CACHE_DEFAULT_CACHE_BYTES: u64 = 10 * GIB;

/// v6.8.0 (CIRISPersist#148) — operator-facing cache presets.
///
/// Each mode maps onto [`ReplicationConfig`] via [`Self::apply_to`].
/// The mapping table (issue #148 §1):
///
/// | Mode  | budget       | utilization | half-life (d) | sweep    |
/// |-------|--------------|-------------|---------------|----------|
/// | Proxy | per-mode     | 0.50        | 0.5           | 30 s     |
/// | Cache | per-mode     | 0.92        | 30.0          | 60 s     |
/// | Server| `u64::MAX`   | 0.92        | 90.0          | 300 s    |
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CacheMode {
    /// Proxy: minimal disk, aggressive eviction. Relay-but-don't-host
    /// peers (mobile, embedded). Short TTL via a 12 h decay half-life
    /// + evict-to-half watermark + frequent (30 s) sweep.
    Proxy {
        /// Hard byte cap. Default [`PROXY_DEFAULT_CACHE_BYTES`].
        max_cache_bytes: u64,
        /// Advisory TTL for proxied content, in seconds. Default
        /// [`PROXY_DEFAULT_TTL_SECONDS`]. Folded into the sweep cadence
        /// (the sweeper's freshness decay is the real eviction driver;
        /// the TTL bounds how often we re-check).
        cache_ttl_seconds: u32,
    },
    /// Cache (middle ground): host popular, evict long-tail. Standard
    /// server / desktop. Uses the existing production defaults.
    Cache {
        /// Hard byte cap. Default [`CACHE_DEFAULT_CACHE_BYTES`].
        max_cache_bytes: u64,
    },
    /// Server: durable host, no cap. Eviction only on explicit
    /// operator command (`sweep_evictions_once`). Backbone nodes.
    /// `storage_budget_bytes = u64::MAX` keeps the background sweeper
    /// idle ([`ReplicationConfig::sweeper_active`] is false).
    Server,
}

impl Default for CacheMode {
    /// Default preserves pre-#148 behavior: Server = unbounded, sweeper
    /// idle. Operators who never opt in see no change (issue #148
    /// anti-rec: "Don't change defaults for existing deployments").
    fn default() -> Self {
        CacheMode::Server
    }
}

impl CacheMode {
    /// The mode's effective byte budget. Proxy/Cache report their cap;
    /// Server is unbounded (`u64::MAX`).
    pub fn budget_bytes(&self) -> u64 {
        match self {
            CacheMode::Proxy {
                max_cache_bytes, ..
            } => *max_cache_bytes,
            CacheMode::Cache { max_cache_bytes } => *max_cache_bytes,
            CacheMode::Server => u64::MAX,
        }
    }

    /// Lower-case stable label (`"proxy" | "cache" | "server"`). Round-
    /// trips with [`Self::mode_from_label`].
    pub fn label(&self) -> &'static str {
        match self {
            CacheMode::Proxy { .. } => "proxy",
            CacheMode::Cache { .. } => "cache",
            CacheMode::Server => "server",
        }
    }

    /// Construct the default-shaped mode for a label. Returns `None`
    /// for an unknown label. Per-mode caps take their documented
    /// defaults; override via [`Self::with_budget_bytes`].
    pub fn mode_from_label(label: &str) -> Option<CacheMode> {
        match label.trim().to_ascii_lowercase().as_str() {
            "proxy" => Some(CacheMode::Proxy {
                max_cache_bytes: PROXY_DEFAULT_CACHE_BYTES,
                cache_ttl_seconds: PROXY_DEFAULT_TTL_SECONDS,
            }),
            "cache" => Some(CacheMode::Cache {
                max_cache_bytes: CACHE_DEFAULT_CACHE_BYTES,
            }),
            "server" => Some(CacheMode::Server),
            _ => None,
        }
    }

    /// Return a copy with the byte cap overridden. No-op on Server
    /// (Server is unbounded by definition — an explicit cap means the
    /// operator wanted Cache mode; we keep Server unbounded and let the
    /// resolution layer pick the mode).
    pub fn with_budget_bytes(self, bytes: u64) -> CacheMode {
        match self {
            CacheMode::Proxy {
                cache_ttl_seconds, ..
            } => CacheMode::Proxy {
                max_cache_bytes: bytes,
                cache_ttl_seconds,
            },
            CacheMode::Cache { .. } => CacheMode::Cache {
                max_cache_bytes: bytes,
            },
            CacheMode::Server => CacheMode::Server,
        }
    }

    /// Fold this preset onto a base [`ReplicationConfig`], returning the
    /// reconfigured config. Preserves the trust-gate knobs
    /// (`trust_threshold`, recursion depths) — this mapping touches
    /// only the *eviction/budget* surface (issue #148 §1 table).
    pub fn apply_to(&self, base: ReplicationConfig) -> ReplicationConfig {
        match self {
            CacheMode::Proxy {
                max_cache_bytes,
                cache_ttl_seconds,
            } => ReplicationConfig {
                storage_budget_bytes: *max_cache_bytes,
                steady_state_utilization: 0.50,
                eviction_decay_half_life_days: 0.5,
                // Sweep at most every cache_ttl, but cap to 30 s so a
                // small TTL doesn't tightloop and a large TTL still
                // sweeps frequently for the proxy use-case.
                sweep_interval: Duration::from_secs((*cache_ttl_seconds as u64).clamp(1, 30)),
                ..base
            },
            CacheMode::Cache { max_cache_bytes } => ReplicationConfig {
                storage_budget_bytes: *max_cache_bytes,
                steady_state_utilization: 0.92,
                eviction_decay_half_life_days: 30.0,
                sweep_interval: Duration::from_secs(60),
                ..base
            },
            CacheMode::Server => ReplicationConfig {
                storage_budget_bytes: u64::MAX,
                steady_state_utilization: 0.92,
                eviction_decay_half_life_days: 90.0,
                sweep_interval: Duration::from_secs(300),
                ..base
            },
        }
    }

    /// Build the effective [`ReplicationConfig`] from defaults +
    /// environment, per the #148 resolution order
    /// (env over mode-default; the kwarg layer sits above this and is
    /// applied by the PyO3 constructor).
    ///
    /// Env vars (all optional):
    /// - `CIRIS_PERSIST_CACHE_MODE` = `proxy|cache|server` (default
    ///   `server` — preserves legacy unbounded behavior).
    /// - `CIRIS_PERSIST_CACHE_BYTES` = human-readable cap
    ///   (`"10GB"` / `"500MB"` / `"100MiB"`) — overrides the mode cap.
    /// - `CIRIS_PERSIST_CACHE_TTL_SECONDS` = Proxy TTL (integer
    ///   seconds).
    ///
    /// Returns `None` when no cache env var is set (caller keeps its
    /// own default), or `Some(mode)` describing the resolved preset.
    pub fn from_env() -> Option<CacheMode> {
        let mode_var = std::env::var("CIRIS_PERSIST_CACHE_MODE").ok();
        let bytes_var = std::env::var("CIRIS_PERSIST_CACHE_BYTES").ok();
        let ttl_var = std::env::var("CIRIS_PERSIST_CACHE_TTL_SECONDS").ok();
        if mode_var.is_none() && bytes_var.is_none() && ttl_var.is_none() {
            return None;
        }

        // Mode label: explicit, else "cache" when only a byte cap was
        // given (a bare CIRIS_PERSIST_CACHE_BYTES means "cache this
        // many bytes" — Cache is the natural mode), else "server".
        let label = match (&mode_var, &bytes_var) {
            (Some(m), _) => m.clone(),
            (None, Some(_)) => "cache".to_string(),
            (None, None) => "server".to_string(),
        };
        let mut mode = CacheMode::mode_from_label(&label)?;

        if let Some(ttl) = ttl_var.as_deref().and_then(|s| s.trim().parse::<u32>().ok()) {
            if let CacheMode::Proxy {
                max_cache_bytes, ..
            } = mode
            {
                mode = CacheMode::Proxy {
                    max_cache_bytes,
                    cache_ttl_seconds: ttl,
                };
            }
        }

        if let Some(raw) = bytes_var.as_deref() {
            if let Ok(bytes) = parse_human_bytes(raw) {
                mode = mode.with_budget_bytes(bytes);
            }
        }

        Some(mode)
    }
}

/// Error parsing a human-readable byte string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid byte size {input:?}: {reason}")]
pub struct ByteParseError {
    /// The offending input.
    pub input: String,
    /// Why it failed.
    pub reason: String,
}

/// v6.8.0 (CIRISPersist#148) — parse a human-readable byte string into
/// a `u64`. Operator-hostile bare `u64` is the problem this solves.
///
/// # Supported units
///
/// **SI / decimal (powers of 1000):** `B`, `KB`, `MB`, `GB`, `TB`,
/// `PB`. **IEC / binary (powers of 1024):** `KiB`, `MiB`, `GiB`,
/// `TiB`, `PiB`. A bare number with no unit is bytes.
///
/// **Disambiguation rule** (documented per issue constraint): a
/// single-letter `K/M/G/T/P` *with* a trailing `B` but *without* `i`
/// is SI (`"10GB"` = 10 × 10⁹). Append `i` for binary (`"10GiB"` =
/// 10 × 2³⁰). This matches `byte-unit` / `humanize` convention and
/// the GNU `--si` distinction. Case-insensitive on the unit prefix;
/// the `i` and `B` are matched case-insensitively too (`"10gib"` ok).
///
/// Fractional values are accepted (`"1.5GB"` → 1_500_000_000) and
/// truncated toward zero after multiplication.
///
/// We hand-roll this (≈40 LOC, fully unit-tested below) rather than
/// add the `byte-unit` crate: the surface is tiny, the dependency
/// graph cost is real, and the disambiguation policy is something we
/// want to own + pin in tests. FLAG: revisit if we need locale-aware
/// or output-formatting features `byte-unit` provides.
pub fn parse_human_bytes(input: &str) -> Result<u64, ByteParseError> {
    let err = |reason: &str| ByteParseError {
        input: input.to_string(),
        reason: reason.to_string(),
    };
    let s = input.trim();
    if s.is_empty() {
        return Err(err("empty"));
    }
    // Split the leading numeric run (digits, one dot, optional sign-free)
    // from the trailing unit.
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let (num_part, unit_part) = s.split_at(split);
    let num_part = num_part.trim();
    let unit = unit_part.trim().to_ascii_lowercase();

    if num_part.is_empty() {
        return Err(err("no numeric component"));
    }
    let value: f64 = num_part
        .parse()
        .map_err(|_| err("numeric component not a number"))?;
    if value < 0.0 || !value.is_finite() {
        return Err(err("must be a finite non-negative number"));
    }

    let multiplier: f64 = match unit.as_str() {
        "" | "b" => 1.0,
        // SI / decimal.
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        "pb" => 1e15,
        // IEC / binary.
        "kib" => 1024f64,
        "mib" => 1024f64.powi(2),
        "gib" => 1024f64.powi(3),
        "tib" => 1024f64.powi(4),
        "pib" => 1024f64.powi(5),
        other => return Err(err(&format!("unknown unit {other:?}"))),
    };

    let bytes = value * multiplier;
    if bytes >= u64::MAX as f64 {
        return Ok(u64::MAX);
    }
    Ok(bytes as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_bytes() {
        assert_eq!(parse_human_bytes("0").unwrap(), 0);
        assert_eq!(parse_human_bytes("1024").unwrap(), 1024);
        assert_eq!(parse_human_bytes("  4096  ").unwrap(), 4096);
        assert_eq!(parse_human_bytes("512B").unwrap(), 512);
    }

    #[test]
    fn parse_si_units_powers_of_1000() {
        assert_eq!(parse_human_bytes("10GB").unwrap(), 10_000_000_000);
        assert_eq!(parse_human_bytes("500MB").unwrap(), 500_000_000);
        assert_eq!(parse_human_bytes("1KB").unwrap(), 1_000);
        assert_eq!(parse_human_bytes("1TB").unwrap(), 1_000_000_000_000);
    }

    #[test]
    fn parse_iec_units_powers_of_1024() {
        assert_eq!(parse_human_bytes("100MiB").unwrap(), 100 * MIB);
        assert_eq!(parse_human_bytes("10GiB").unwrap(), 10 * GIB);
        assert_eq!(parse_human_bytes("1KiB").unwrap(), 1024);
    }

    #[test]
    fn parse_si_iec_disambiguation_documented() {
        // "GB" (SI) != "GiB" (IEC) — the core operator-facing contract.
        assert_eq!(parse_human_bytes("1GB").unwrap(), 1_000_000_000);
        assert_eq!(parse_human_bytes("1GiB").unwrap(), 1_073_741_824);
        assert_ne!(
            parse_human_bytes("1GB").unwrap(),
            parse_human_bytes("1GiB").unwrap()
        );
    }

    #[test]
    fn parse_case_insensitive_and_fractional() {
        assert_eq!(parse_human_bytes("10gib").unwrap(), 10 * GIB);
        assert_eq!(parse_human_bytes("10Gb").unwrap(), 10_000_000_000);
        assert_eq!(parse_human_bytes("1.5GB").unwrap(), 1_500_000_000);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_human_bytes("").is_err());
        assert!(parse_human_bytes("GB").is_err());
        assert!(parse_human_bytes("10XB").is_err());
        assert!(parse_human_bytes("-5GB").is_err());
        assert!(parse_human_bytes("abc").is_err());
    }

    #[test]
    fn proxy_preset_maps_aggressive() {
        let m = CacheMode::Proxy {
            max_cache_bytes: 100 * MIB,
            cache_ttl_seconds: 60,
        };
        let cfg = m.apply_to(ReplicationConfig::default());
        assert_eq!(cfg.storage_budget_bytes, 100 * MIB);
        assert_eq!(cfg.steady_state_utilization, 0.50);
        assert_eq!(cfg.eviction_decay_half_life_days, 0.5);
        assert!(cfg.sweeper_active());
        // ttl 60 capped to 30s sweep.
        assert_eq!(cfg.sweep_interval, Duration::from_secs(30));
    }

    #[test]
    fn cache_preset_maps_standard_defaults() {
        let m = CacheMode::Cache {
            max_cache_bytes: 10 * GIB,
        };
        let cfg = m.apply_to(ReplicationConfig::default());
        assert_eq!(cfg.storage_budget_bytes, 10 * GIB);
        assert_eq!(cfg.steady_state_utilization, 0.92);
        assert_eq!(cfg.eviction_decay_half_life_days, 30.0);
        assert_eq!(cfg.sweep_interval, Duration::from_secs(60));
        assert!(cfg.sweeper_active());
    }

    #[test]
    fn server_preset_is_unbounded_and_idle() {
        let cfg = CacheMode::Server.apply_to(ReplicationConfig::default());
        assert_eq!(cfg.storage_budget_bytes, u64::MAX);
        assert!(!cfg.sweeper_active());
        assert_eq!(cfg.eviction_decay_half_life_days, 90.0);
        assert_eq!(cfg.sweep_interval, Duration::from_secs(300));
    }

    #[test]
    fn apply_to_preserves_trust_knobs() {
        let base = ReplicationConfig {
            trust_threshold: 0.7,
            trust_recursion_depth: 2,
            ..Default::default()
        };
        let cfg = CacheMode::Cache {
            max_cache_bytes: GIB,
        }
        .apply_to(base);
        assert_eq!(cfg.trust_threshold, 0.7);
        assert_eq!(cfg.trust_recursion_depth, 2);
    }

    #[test]
    fn label_roundtrips() {
        assert_eq!(CacheMode::Server.label(), "server");
        assert_eq!(
            CacheMode::mode_from_label("PROXY").map(|m| m.label()),
            Some("proxy")
        );
        assert_eq!(
            CacheMode::mode_from_label("cache").map(|m| m.budget_bytes()),
            Some(CACHE_DEFAULT_CACHE_BYTES)
        );
        assert_eq!(CacheMode::mode_from_label("bogus"), None);
    }

    #[test]
    fn with_budget_overrides_cap_not_server() {
        let p = CacheMode::mode_from_label("proxy")
            .unwrap()
            .with_budget_bytes(7 * MIB);
        assert_eq!(p.budget_bytes(), 7 * MIB);
        // Server stays unbounded even if a budget is suggested.
        assert_eq!(
            CacheMode::Server.with_budget_bytes(123).budget_bytes(),
            u64::MAX
        );
    }
}
