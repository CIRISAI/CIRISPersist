//! v62.0.0 (slice D, readiness P4/P12) — **the seams over the `ciris:node`
//! host ABI** (feature `host-abi`, CIRISVerify's `ciris-host-abi`).
//!
//! A NODE build (the top-level module crate) turns `host-abi` on and installs
//! these: [`AbiClock`] as the [`Clock`](super::Clock)
//! (`ciris:node/clock.monotonic-us` / `wall-ms`), and [`AbiFreeBytes`] as the
//! disk-pressure monitor's
//! [`FreeBytesSource`](crate::federation::FreeBytesSource)
//! (`ciris:node/storage` `volume.free-bytes`, replacing fs4's statvfs).
//!
//! **Randomness is not here.** Persist draws through `getrandom` (uuid
//! `rng-getrandom`, `rand_core::OsRng`, the ML-DSA / Ed25519 key paths). The
//! custom backend over `ciris:node/random.fill` is defined ONCE, by the
//! top-level node crate, which enables `ciris-host-abi/getrandom-backend` and
//! builds with `--cfg getrandom_backend="custom"` for
//! `wasm32-unknown-unknown`. Persist never defines a getrandom symbol
//! (docs/WASM_NODE_BUILD.md).

use std::time::Duration;

use chrono::{DateTime, Utc};

/// The host's clock through `ciris:node/clock`.
///
/// `wall-ms` is `None` until the host trusts its time (`event.clock-trusted`
/// fires once when it first becomes some). Persist's [`Clock::now`]
/// cannot say "untrusted", so an untrusted read answers the Unix epoch: a
/// signed row stamped then is refused by every peer's freshness window, never
/// passed off as current. A node must not build its Engine, or stamp anything,
/// before `clock-trusted` (CIRISVerify `ciris-host-abi` README, "Clock
/// trust"); [`AbiClock::trusted`] answers it.
///
/// [`Clock::now`]: super::Clock::now
#[derive(Debug, Default, Clone, Copy)]
pub struct AbiClock;

impl AbiClock {
    /// Whether the host trusts its wall time yet.
    #[must_use]
    pub fn trusted() -> bool {
        ciris_host_abi::clock::wall_ms().is_some()
    }
}

impl super::Clock for AbiClock {
    fn now(&self) -> DateTime<Utc> {
        ciris_host_abi::clock::wall_ms()
            .and_then(DateTime::<Utc>::from_timestamp_millis)
            .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
    }

    fn monotonic(&self) -> Duration {
        Duration::from_micros(ciris_host_abi::clock::monotonic_us())
    }
}

/// The primary volume's free bytes through `ciris:node/storage`. The path the
/// monitor passes is ignored: a node holds no paths, only the volume its host
/// opened (FSD §4.1 rule 3). A host that cannot say answers `None`, which is
/// an I/O error here, so the monitor keeps its prior tier rather than
/// downgrading protection (its read-failure rule).
#[derive(Debug, Default, Clone, Copy)]
pub struct AbiFreeBytes;

impl crate::federation::FreeBytesSource for AbiFreeBytes {
    fn free_bytes(&self, _path: &std::path::Path) -> std::io::Result<u64> {
        ciris_host_abi::storage::primary()
            .free_bytes()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "ciris:node/storage volume.free-bytes: the host does not say",
                )
            })
    }
}
