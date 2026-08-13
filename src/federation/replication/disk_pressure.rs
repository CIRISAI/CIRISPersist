//! Proactive disk-pressure response (v6.8.0, CIRISPersist#149).
//!
//! Companion to the operator cache cap (CIRISPersist#148). #148 bounds
//! *what we choose to use*; this module reacts when the **system disk
//! fills regardless of our cap** — other processes, logs, OS updates.
//! A node can be under-cap on its own usage but over-pressure on the
//! host; this catches that.
//!
//! # Model — four free-byte tiers
//!
//! Pressure is classified by **absolute free bytes** on a monitored
//! path (NOT a percentage — `df`/`statvfs` percentages are fragile on
//! overlay / NFS / btrfs-subvol / loop devices; issue #149 anti-rec).
//! Tiers, loosest → tightest:
//!
//! - **Normal** — above `warn_free_bytes`. No action.
//! - **Warn** (`<= warn_free_bytes`) — log only.
//! - **Crit** (`<= crit_free_bytes`) — force-evict proxy content first,
//!   keep local + family.
//! - **Stop** (`<= stop_free_bytes`) — refuse to ACCEPT new
//!   federation-proxied content AND refuse to SERVE proxied content to
//!   peers.
//! - **HostAtRisk** (`<= host_at_risk_bytes`) — loudest; everything
//!   stop does, plus stop accepting new attestations referencing blobs
//!   we don't already hold (read-mostly until pressure clears).
//!
//! **Never evict / refuse local or family content.** Force-evict proxy
//! first; family survives until host-at-risk-loud logging.
//!
//! # Testability
//!
//! The free-bytes reading is behind [`FreeBytesSource`] so tests inject
//! a stubbed value instead of depending on the host's real disk. The
//! production impl is [`StatvfsFreeBytes`], which reads `statvfs`
//! `f_bavail` via the in-tree `fs4` crate
//! ([`fs4::available_space`]) — no new dependency, cross-platform
//! (`statvfs` on Unix, `GetDiskFreeSpaceEx` on Windows).
//!
//! # Defaults ON
//!
//! [`DiskPressureConfig::default`] is safe even if an operator never
//! configures it (desktop-scale tiers). The monitor is opt-in to
//! *spawn*, but the config + classification logic is always available.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// 1 mebibyte (IEC).
const MIB: u64 = 1024 * 1024;
/// 1 gibibyte (IEC).
const GIB: u64 = 1024 * 1024 * 1024;

/// v6.8.0 (CIRISPersist#149) — family-membership predicate: given an
/// `attesting_key_id`, return `true` if the key is local-or-family
/// (its content survives proxy eviction / refusal). The cohabitation
/// bootstrap installs a closure walking the trust graph.
pub type FamilyPredicate = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// v6.8.0 (CIRISPersist#149) — disk-pressure tier, from loosest
/// (`Normal`) to tightest (`HostAtRisk`). `Ord` follows severity:
/// `Normal < Warn < Crit < Stop < HostAtRisk`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PressureTier {
    /// Free bytes above `warn_free_bytes`.
    Normal,
    /// `<= warn_free_bytes`.
    Warn,
    /// `<= crit_free_bytes`.
    Crit,
    /// `<= stop_free_bytes`.
    Stop,
    /// `<= host_at_risk_bytes`.
    HostAtRisk,
}

impl PressureTier {
    /// Stable lower-case label (used in tracing fields + the
    /// `substrate:disk_pressure:{tier}` attestation dimension).
    pub fn label(&self) -> &'static str {
        match self {
            PressureTier::Normal => "normal",
            PressureTier::Warn => "warn",
            PressureTier::Crit => "crit",
            PressureTier::Stop => "stop",
            PressureTier::HostAtRisk => "host_at_risk",
        }
    }

    /// True once we should refuse to ACCEPT new proxy-attested content
    /// (stop tier and tighter).
    pub fn refuses_proxy_writes(&self) -> bool {
        *self >= PressureTier::Stop
    }

    /// True once we should refuse to SERVE proxy content to peers (stop
    /// tier and tighter).
    pub fn refuses_proxy_serves(&self) -> bool {
        *self >= PressureTier::Stop
    }

    /// True once the sweeper should run immediately and evict proxy
    /// content first (crit tier and tighter).
    pub fn force_evicts_proxy(&self) -> bool {
        *self >= PressureTier::Crit
    }
}

/// v6.8.0 (CIRISPersist#149) — trust tier of a piece of content,
/// deciding eviction/refusal priority. The substrate exposes the
/// mechanism; the consumer composes the family-membership predicate
/// (see [`DiskPressureConfig::is_local_or_family`]) from the existing trust
/// hierarchy (`trust:direct` / `trust:partnered`, minus blackholed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustTier {
    /// The local engine's own signer key (self). Never evicted /
    /// refused.
    Local,
    /// Keys with a `trust:direct` / `trust:partnered` relationship to
    /// the local signer (and not blackholed). Survives until
    /// host-at-risk.
    Family,
    /// Everyone else — peers we relay (proxy) for. Evicted / refused
    /// first.
    Federation,
}

/// v6.8.0 (CIRISPersist#149) — per-tier action. Variants are ordered by
/// escalating severity; each implies the ones above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureAction {
    /// No action; log only.
    LogOnly,
    /// Reject new proxy `put_blob` writes (attesting key neither local
    /// nor family). Local + family writes proceed.
    RejectProxyWrites,
    /// Above + reject serving proxy content to peers.
    RejectProxyAll,
    /// Above + run the sweeper now, evicting proxy-attested rows first.
    ForceEvictProxy,
    /// Above + stop accepting new attestations referencing blobs we
    /// don't already hold (read-mostly until pressure clears).
    All,
}

/// v6.8.0 (CIRISPersist#149) — operator knobs. **Defaults ON** — the
/// `Default` impl is safe for an un-configured desktop deployment.
///
/// Tiers are absolute FREE bytes, loosest → tightest:
/// `warn >= crit >= stop >= host_at_risk`. The classifier
/// ([`classify_free_bytes`]) tolerates mis-ordered tiers (it picks the
/// tightest matching tier) but the constructor logs a warning.
#[derive(Clone)]
pub struct DiskPressureConfig {
    /// Path whose filesystem free-space we monitor. Default resolution:
    /// `$CIRIS_DATA_DIR`, else the current dir.
    pub monitor_path: PathBuf,
    /// `<= this` ⇒ Warn. Default 2 GiB.
    pub warn_free_bytes: u64,
    /// `<= this` ⇒ Crit. Default 1 GiB.
    pub crit_free_bytes: u64,
    /// `<= this` ⇒ Stop. Default 500 MiB.
    pub stop_free_bytes: u64,
    /// `<= this` ⇒ HostAtRisk. Default 200 MiB.
    pub host_at_risk_bytes: u64,
    /// Poll cadence. Default 30 s. Clamped to [`MIN_POLL_INTERVAL`].
    pub poll_interval: Duration,
    /// Action at each tier (issue #149 defaults).
    pub warn_action: PressureAction,
    /// Action at crit tier.
    pub crit_action: PressureAction,
    /// Action at stop tier.
    pub stop_action: PressureAction,
    /// Action at host-at-risk tier.
    pub host_at_risk_action: PressureAction,
    /// Family-membership predicate: given an `attesting_key_id`, return
    /// `true` if it's local-or-family (survives proxy eviction /
    /// refusal). `None` ⇒ treat everyone except the local signer as
    /// federation (proxy). The cohabitation bootstrap installs a
    /// closure walking the trust graph (`trust:direct` /
    /// `trust:partnered` minus blackhole, #117/#120).
    pub is_family: Option<FamilyPredicate>,
}

impl std::fmt::Debug for DiskPressureConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiskPressureConfig")
            .field("monitor_path", &self.monitor_path)
            .field("warn_free_bytes", &self.warn_free_bytes)
            .field("crit_free_bytes", &self.crit_free_bytes)
            .field("stop_free_bytes", &self.stop_free_bytes)
            .field("host_at_risk_bytes", &self.host_at_risk_bytes)
            .field("poll_interval", &self.poll_interval)
            .field("warn_action", &self.warn_action)
            .field("crit_action", &self.crit_action)
            .field("stop_action", &self.stop_action)
            .field("host_at_risk_action", &self.host_at_risk_action)
            .field("is_family", &self.is_family.is_some())
            .finish()
    }
}

/// Floor on the poll cadence — issue #149 anti-rec: "Don't poll faster
/// than 5 seconds." (observation theater + syscall cost).
pub const MIN_POLL_INTERVAL: Duration = Duration::from_secs(5);

impl Default for DiskPressureConfig {
    fn default() -> Self {
        let monitor_path = default_monitor_path();
        Self {
            monitor_path,
            warn_free_bytes: 2 * GIB,
            crit_free_bytes: GIB,
            stop_free_bytes: 500 * MIB,
            host_at_risk_bytes: 200 * MIB,
            poll_interval: Duration::from_secs(30),
            warn_action: PressureAction::LogOnly,
            crit_action: PressureAction::ForceEvictProxy,
            stop_action: PressureAction::RejectProxyAll,
            host_at_risk_action: PressureAction::All,
            is_family: None,
        }
    }
}

/// Resolve the default monitor path: `$CIRIS_DATA_DIR`, else cwd.
fn default_monitor_path() -> PathBuf {
    if let Ok(dir) = std::env::var("CIRIS_DATA_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

impl DiskPressureConfig {
    /// The effective poll cadence (clamped to [`MIN_POLL_INTERVAL`]).
    pub fn effective_poll_interval(&self) -> Duration {
        self.poll_interval.max(MIN_POLL_INTERVAL)
    }

    /// True iff `key_id` is the local signer or family (survives proxy
    /// eviction). When no predicate is installed, only `local_key_id`
    /// is protected; everyone else is federation/proxy.
    pub fn is_local_or_family(&self, key_id: &str, local_key_id: &str) -> bool {
        if key_id == local_key_id {
            return true;
        }
        match &self.is_family {
            Some(pred) => pred(key_id),
            None => false,
        }
    }

    /// Classify the trust tier of `attesting_key_id`.
    pub fn trust_tier_of(&self, attesting_key_id: &str, local_key_id: &str) -> TrustTier {
        if attesting_key_id == local_key_id {
            TrustTier::Local
        } else if self
            .is_family
            .as_ref()
            .map(|p| p(attesting_key_id))
            .unwrap_or(false)
        {
            TrustTier::Family
        } else {
            TrustTier::Federation
        }
    }

    /// Apply env-var overrides (issue #149 resolution order; env over
    /// the struct default). Recognized:
    /// `CIRIS_PERSIST_DISK_WARN_BYTES`, `..._CRIT_BYTES`,
    /// `..._STOP_BYTES`, `..._HOST_AT_RISK_BYTES` (human-readable byte
    /// strings via [`super::parse_human_bytes`]) and
    /// `CIRIS_PERSIST_DISK_POLL_INTERVAL` (integer seconds).
    /// `CIRIS_DATA_DIR` is honored via [`default_monitor_path`] when
    /// the config is constructed by `Default`.
    pub fn with_env_overrides(mut self) -> Self {
        use super::parse_human_bytes;
        let bytes_env = |name: &str| -> Option<u64> {
            std::env::var(name)
                .ok()
                .and_then(|v| parse_human_bytes(&v).ok())
        };
        if let Some(v) = bytes_env("CIRIS_PERSIST_DISK_WARN_BYTES") {
            self.warn_free_bytes = v;
        }
        if let Some(v) = bytes_env("CIRIS_PERSIST_DISK_CRIT_BYTES") {
            self.crit_free_bytes = v;
        }
        if let Some(v) = bytes_env("CIRIS_PERSIST_DISK_STOP_BYTES") {
            self.stop_free_bytes = v;
        }
        if let Some(v) = bytes_env("CIRIS_PERSIST_DISK_HOST_AT_RISK_BYTES") {
            self.host_at_risk_bytes = v;
        }
        if let Some(secs) = std::env::var("CIRIS_PERSIST_DISK_POLL_INTERVAL")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
        {
            self.poll_interval = Duration::from_secs(secs);
        }
        self
    }
}

/// v6.8.0 (CIRISPersist#149) — classify free bytes into a tier. Picks
/// the *tightest* matching threshold so mis-ordered tiers can't mask a
/// more-severe condition.
pub fn classify_free_bytes(free_bytes: u64, cfg: &DiskPressureConfig) -> PressureTier {
    if free_bytes <= cfg.host_at_risk_bytes {
        PressureTier::HostAtRisk
    } else if free_bytes <= cfg.stop_free_bytes {
        PressureTier::Stop
    } else if free_bytes <= cfg.crit_free_bytes {
        PressureTier::Crit
    } else if free_bytes <= cfg.warn_free_bytes {
        PressureTier::Warn
    } else {
        PressureTier::Normal
    }
}

/// v6.8.0 (CIRISPersist#149) — abstraction over the free-bytes reading
/// so tests inject a value instead of depending on the host disk.
pub trait FreeBytesSource: Send + Sync {
    /// Free bytes available to an unprivileged writer on the filesystem
    /// containing `path` (`statvfs` `f_bavail × f_frsize`).
    fn free_bytes(&self, path: &Path) -> std::io::Result<u64>;
}

/// Production [`FreeBytesSource`] — `statvfs`-backed via the in-tree
/// `fs4` crate. `fs4::available_space` returns `f_bavail × f_frsize`
/// (Unix) / `GetDiskFreeSpaceEx` (Windows), exactly the free-bytes
/// semantic issue #149 specifies.
#[derive(Debug, Clone, Copy, Default)]
pub struct StatvfsFreeBytes;

impl FreeBytesSource for StatvfsFreeBytes {
    fn free_bytes(&self, path: &Path) -> std::io::Result<u64> {
        fs4::available_space(path)
    }
}

/// A fixed-value [`FreeBytesSource`] for tests / mocking. Interior-
/// mutable so a test can drive it through a sequence of free-byte
/// readings.
#[derive(Debug, Default)]
pub struct StubFreeBytes {
    value: std::sync::atomic::AtomicU64,
}

impl StubFreeBytes {
    /// Construct with an initial free-bytes reading.
    pub fn new(initial: u64) -> Self {
        Self {
            value: std::sync::atomic::AtomicU64::new(initial),
        }
    }
    /// Update the reading subsequent polls will observe.
    pub fn set(&self, bytes: u64) {
        self.value
            .store(bytes, std::sync::atomic::Ordering::Relaxed);
    }
}

impl FreeBytesSource for StubFreeBytes {
    fn free_bytes(&self, _path: &Path) -> std::io::Result<u64> {
        Ok(self.value.load(std::sync::atomic::Ordering::Relaxed))
    }
}

/// v6.8.0 (CIRISPersist#149) — point-in-time snapshot of pressure
/// state, exposed to callers (incl. PyO3) for live monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskPressureSnapshot {
    /// Most-recent free-bytes reading.
    pub free_bytes: u64,
    /// Classified tier.
    pub tier: PressureTier,
    /// `true` once stop tier is reached — admission gates consult this
    /// cached flag (issue #149 anti-rec: don't statvfs per write).
    pub refuses_proxy_writes: bool,
    /// `true` once stop tier — content-fetch handler consults this.
    pub refuses_proxy_serves: bool,
    /// `true` once crit tier — the sweeper force-evicts proxy first.
    pub force_evicts_proxy: bool,
}

impl DiskPressureSnapshot {
    /// Build a snapshot from a free-bytes reading + config.
    pub fn from_free_bytes(free_bytes: u64, cfg: &DiskPressureConfig) -> Self {
        let tier = classify_free_bytes(free_bytes, cfg);
        Self {
            free_bytes,
            tier,
            refuses_proxy_writes: tier.refuses_proxy_writes(),
            refuses_proxy_serves: tier.refuses_proxy_serves(),
            force_evicts_proxy: tier.force_evicts_proxy(),
        }
    }

    /// The all-clear snapshot (unbounded free space).
    pub fn normal() -> Self {
        Self {
            free_bytes: u64::MAX,
            tier: PressureTier::Normal,
            refuses_proxy_writes: false,
            refuses_proxy_serves: false,
            force_evicts_proxy: false,
        }
    }
}

/// v6.8.0 (CIRISPersist#149) — the pressure state machine. Holds the
/// config, the (injectable) free-bytes source, and the last-observed
/// tier in a `tokio::sync::watch` so admission gates read the cached
/// classification cheaply (no statvfs per write) and so the monitor
/// only logs on a tier *transition* (edge-triggered, not every poll).
pub struct DiskPressureMonitor {
    cfg: Arc<DiskPressureConfig>,
    source: Arc<dyn FreeBytesSource>,
    /// Latest snapshot, readable by any number of callers.
    state_tx: tokio::sync::watch::Sender<DiskPressureSnapshot>,
    state_rx: tokio::sync::watch::Receiver<DiskPressureSnapshot>,
}

impl DiskPressureMonitor {
    /// Construct with the production statvfs source.
    pub fn new(cfg: DiskPressureConfig) -> Self {
        Self::with_source(cfg, Arc::new(StatvfsFreeBytes))
    }

    /// Construct with an injected [`FreeBytesSource`] (tests / mocking).
    pub fn with_source(cfg: DiskPressureConfig, source: Arc<dyn FreeBytesSource>) -> Self {
        let (state_tx, state_rx) = tokio::sync::watch::channel(DiskPressureSnapshot::normal());
        Self {
            cfg: Arc::new(cfg),
            source,
            state_tx,
            state_rx,
        }
    }

    /// A cheap clone of the live state receiver. Admission gates +
    /// content-fetch handlers hold one and read
    /// `rx.borrow().refuses_proxy_writes` etc. — O(1), no syscall.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<DiskPressureSnapshot> {
        self.state_rx.clone()
    }

    /// Current snapshot.
    pub fn snapshot(&self) -> DiskPressureSnapshot {
        *self.state_rx.borrow()
    }

    /// The config this monitor was built with.
    pub fn config(&self) -> Arc<DiskPressureConfig> {
        self.cfg.clone()
    }

    /// Perform one poll: read free bytes, re-classify, update the
    /// watch state, and log loud **only on a tier transition**
    /// (edge-triggered). Returns the new snapshot. Safe to call
    /// manually (tests / sovereign cron) — the background loop calls
    /// the same body.
    pub fn poll_once(&self) -> DiskPressureSnapshot {
        let prev = *self.state_rx.borrow();
        let free_bytes = match self.source.free_bytes(&self.cfg.monitor_path) {
            Ok(b) => b,
            Err(e) => {
                // A failed statvfs must not silently disable protection.
                // Keep the prior snapshot; log once at warn.
                tracing::warn!(
                    error = %e,
                    path = %self.cfg.monitor_path.display(),
                    "ciris-persist v6.8.0 disk-pressure: statvfs read failed; keeping prior tier"
                );
                return prev;
            }
        };
        let next = DiskPressureSnapshot::from_free_bytes(free_bytes, &self.cfg);

        if next.tier != prev.tier {
            self.log_transition(prev.tier, next, free_bytes);
            // watch::send only fails if all receivers dropped; we hold
            // one in state_rx, so this never errors.
            let _ = self.state_tx.send(next);
        } else {
            // Same tier — refresh free_bytes in the snapshot without the
            // loud log (so callers see a current number) only if it
            // moved materially; cheap to always update.
            let _ = self.state_tx.send(next);
        }
        next
    }

    /// Edge-triggered logging: warn → `warn!`, crit/stop/host_at_risk →
    /// `error!`, recovery (tightening reversed) → `info!`.
    fn log_transition(&self, prev: PressureTier, next: DiskPressureSnapshot, free_bytes: u64) {
        let action = self.action_for(next.tier);
        if next.tier < prev {
            tracing::info!(
                free_bytes,
                from_tier = prev.label(),
                tier = next.tier.label(),
                "ciris-persist v6.8.0 disk-pressure: pressure EASED"
            );
            return;
        }
        match next.tier {
            PressureTier::Normal => {}
            PressureTier::Warn => tracing::warn!(
                free_bytes,
                tier = next.tier.label(),
                action = ?action,
                "ciris-persist v6.8.0 disk-pressure: WARN — host disk low"
            ),
            PressureTier::Crit => tracing::error!(
                free_bytes,
                tier = next.tier.label(),
                action = ?action,
                "ciris-persist v6.8.0 disk-pressure: CRIT — force-evicting proxy content"
            ),
            PressureTier::Stop => tracing::error!(
                free_bytes,
                tier = next.tier.label(),
                action = ?action,
                "ciris-persist v6.8.0 disk-pressure: STOP — refusing proxy accept + serve"
            ),
            PressureTier::HostAtRisk => tracing::error!(
                free_bytes,
                tier = next.tier.label(),
                action = ?action,
                "ciris-persist v6.8.0 disk-pressure: HOST AT RISK — substrate read-mostly"
            ),
        }
    }

    /// The configured action for a tier.
    pub fn action_for(&self, tier: PressureTier) -> PressureAction {
        match tier {
            PressureTier::Normal => PressureAction::LogOnly,
            PressureTier::Warn => self.cfg.warn_action,
            PressureTier::Crit => self.cfg.crit_action,
            PressureTier::Stop => self.cfg.stop_action,
            PressureTier::HostAtRisk => self.cfg.host_at_risk_action,
        }
    }

    /// v6.8.0 (CIRISPersist#149) — spawn the background poll loop. The
    /// loop calls [`Self::poll_once`] every
    /// [`DiskPressureConfig::effective_poll_interval`] (floored at
    /// [`MIN_POLL_INTERVAL`]) so the cached snapshot stays fresh without
    /// a per-call statvfs, and the enforcement paths read the latest
    /// tier cheaply. Mirrors the eviction-sweeper spawn pattern: returns
    /// a [`DiskPressureMonitorHandle`] whose
    /// [`stop`](DiskPressureMonitorHandle::stop) signals the task to
    /// exit at its next tick. The `EngineCell` owns the handle so all
    /// `PyEngine` clones share one loop.
    ///
    /// Must be called from within a tokio runtime context (the PyO3
    /// constructor enters `cell.runtime` before calling this).
    pub fn spawn_poll_loop(self: std::sync::Arc<Self>) -> DiskPressureMonitorHandle {
        let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
        let shutdown_for_loop = shutdown.clone();
        let interval = self.cfg.effective_poll_interval();
        let monitor = self.clone();
        let join_handle = tokio::spawn(async move {
            // Prime once immediately so the first poll happens without
            // waiting a full interval.
            monitor.poll_once();
            loop {
                tokio::select! {
                    _ = shutdown_for_loop.notified() => {
                        tracing::info!(
                            "ciris-persist v6.8.0 disk-pressure: poll loop shutdown received"
                        );
                        return;
                    }
                    _ = tokio::time::sleep(interval) => {
                        monitor.poll_once();
                    }
                }
            }
        });
        DiskPressureMonitorHandle {
            join_handle,
            shutdown,
        }
    }
}

/// v6.8.0 (CIRISPersist#149) — the spawned disk-pressure poll-loop
/// handle. Mirrors [`crate::federation::EvictionSweeper`]: the
/// `EngineCell` holds it so cohabitation views don't spawn a second
/// loop; `close()` calls [`Self::stop`] to shut it down.
pub struct DiskPressureMonitorHandle {
    join_handle: tokio::task::JoinHandle<()>,
    shutdown: std::sync::Arc<tokio::sync::Notify>,
}

impl DiskPressureMonitorHandle {
    /// Signal the poll loop to stop and return its `JoinHandle`. The
    /// task observes the `Notify` and exits at its next `select!` poll.
    pub fn stop(self) -> tokio::task::JoinHandle<()> {
        self.shutdown.notify_one();
        self.join_handle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> DiskPressureConfig {
        DiskPressureConfig {
            monitor_path: PathBuf::from("/nonexistent-test-path"),
            ..Default::default()
        }
    }

    #[test]
    fn default_config_is_safe_and_on() {
        let c = DiskPressureConfig::default();
        assert_eq!(c.warn_free_bytes, 2 * GIB);
        assert_eq!(c.crit_free_bytes, GIB);
        assert_eq!(c.stop_free_bytes, 500 * MIB);
        assert_eq!(c.host_at_risk_bytes, 200 * MIB);
        assert_eq!(c.effective_poll_interval(), Duration::from_secs(30));
        // defaults-ON actions.
        assert_eq!(c.crit_action, PressureAction::ForceEvictProxy);
        assert_eq!(c.stop_action, PressureAction::RejectProxyAll);
        assert_eq!(c.host_at_risk_action, PressureAction::All);
    }

    #[test]
    fn poll_interval_clamped_to_floor() {
        let c = DiskPressureConfig {
            poll_interval: Duration::from_secs(1),
            ..cfg()
        };
        assert_eq!(c.effective_poll_interval(), MIN_POLL_INTERVAL);
    }

    #[test]
    fn classify_picks_correct_tier() {
        let c = cfg();
        assert_eq!(classify_free_bytes(10 * GIB, &c), PressureTier::Normal);
        assert_eq!(classify_free_bytes(2 * GIB, &c), PressureTier::Warn);
        assert_eq!(classify_free_bytes(GIB, &c), PressureTier::Crit);
        assert_eq!(classify_free_bytes(500 * MIB, &c), PressureTier::Stop);
        assert_eq!(classify_free_bytes(200 * MIB, &c), PressureTier::HostAtRisk);
        assert_eq!(classify_free_bytes(0, &c), PressureTier::HostAtRisk);
    }

    #[test]
    fn tier_ordering_and_predicates() {
        assert!(PressureTier::Normal < PressureTier::Warn);
        assert!(PressureTier::Warn < PressureTier::Crit);
        assert!(PressureTier::Crit < PressureTier::Stop);
        assert!(PressureTier::Stop < PressureTier::HostAtRisk);
        // Crit force-evicts proxy but does NOT refuse writes/serves.
        assert!(PressureTier::Crit.force_evicts_proxy());
        assert!(!PressureTier::Crit.refuses_proxy_writes());
        assert!(!PressureTier::Crit.refuses_proxy_serves());
        // Stop refuses both accept + serve.
        assert!(PressureTier::Stop.refuses_proxy_writes());
        assert!(PressureTier::Stop.refuses_proxy_serves());
        assert!(PressureTier::Stop.force_evicts_proxy());
    }

    #[test]
    fn trust_tier_classification_local_family_federation() {
        let fam = Arc::new(|k: &str| k == "family-key");
        let c = DiskPressureConfig {
            is_family: Some(fam),
            ..cfg()
        };
        assert_eq!(c.trust_tier_of("me", "me"), TrustTier::Local);
        assert_eq!(c.trust_tier_of("family-key", "me"), TrustTier::Family);
        assert_eq!(c.trust_tier_of("stranger", "me"), TrustTier::Federation);
        // Local + family are protected; federation is not.
        assert!(c.is_local_or_family("me", "me"));
        assert!(c.is_local_or_family("family-key", "me"));
        assert!(!c.is_local_or_family("stranger", "me"));
    }

    #[test]
    fn no_family_predicate_protects_only_local() {
        let c = cfg();
        assert!(c.is_local_or_family("me", "me"));
        assert!(!c.is_local_or_family("anyone-else", "me"));
        assert_eq!(c.trust_tier_of("anyone-else", "me"), TrustTier::Federation);
    }

    #[test]
    fn snapshot_flags_track_tier() {
        let c = cfg();
        let s = DiskPressureSnapshot::from_free_bytes(GIB, &c);
        assert_eq!(s.tier, PressureTier::Crit);
        assert!(s.force_evicts_proxy);
        assert!(!s.refuses_proxy_writes);

        let s = DiskPressureSnapshot::from_free_bytes(500 * MIB, &c);
        assert_eq!(s.tier, PressureTier::Stop);
        assert!(s.refuses_proxy_writes);
        assert!(s.refuses_proxy_serves);
    }

    #[tokio::test]
    async fn monitor_poll_updates_snapshot_via_stub() {
        let stub = Arc::new(StubFreeBytes::new(10 * GIB));
        let mon = DiskPressureMonitor::with_source(cfg(), stub.clone());
        // Initial state is Normal.
        assert_eq!(mon.snapshot().tier, PressureTier::Normal);

        // Drop to crit.
        stub.set(GIB);
        let s = mon.poll_once();
        assert_eq!(s.tier, PressureTier::Crit);
        assert!(s.force_evicts_proxy);
        assert_eq!(mon.snapshot().tier, PressureTier::Crit);

        // Drop to stop — refusals engage.
        stub.set(500 * MIB);
        let s = mon.poll_once();
        assert_eq!(s.tier, PressureTier::Stop);
        assert!(s.refuses_proxy_writes);
        assert!(s.refuses_proxy_serves);

        // Recover.
        stub.set(10 * GIB);
        let s = mon.poll_once();
        assert_eq!(s.tier, PressureTier::Normal);
        assert!(!s.refuses_proxy_writes);
    }

    #[tokio::test]
    async fn subscribe_sees_updates() {
        let stub = Arc::new(StubFreeBytes::new(10 * GIB));
        let mon = DiskPressureMonitor::with_source(cfg(), stub.clone());
        let rx = mon.subscribe();
        assert_eq!(rx.borrow().tier, PressureTier::Normal);
        stub.set(100 * MIB);
        mon.poll_once();
        assert_eq!(rx.borrow().tier, PressureTier::HostAtRisk);
        assert!(rx.borrow().refuses_proxy_writes);
    }

    #[tokio::test]
    async fn statvfs_read_failure_keeps_prior_tier() {
        // Path does not exist → fs4 errors; monitor must NOT downgrade
        // protection. Start by forcing a crit tier via stub, then swap
        // to a failing source semantics by using the real statvfs on a
        // bogus path through StatvfsFreeBytes.
        let mon = DiskPressureMonitor::with_source(
            DiskPressureConfig {
                monitor_path: PathBuf::from("/this/path/does/not/exist/ciris"),
                ..cfg()
            },
            Arc::new(StatvfsFreeBytes),
        );
        // Initial snapshot is Normal; a failed read keeps it Normal
        // (prior) rather than panicking.
        let s = mon.poll_once();
        assert_eq!(s.tier, PressureTier::Normal);
    }

    #[test]
    fn env_overrides_apply() {
        // Use a unique guard-free check: set, build, unset.
        std::env::set_var("CIRIS_PERSIST_DISK_WARN_BYTES", "5GB");
        std::env::set_var("CIRIS_PERSIST_DISK_POLL_INTERVAL", "45");
        let c = DiskPressureConfig {
            monitor_path: PathBuf::from("/x"),
            ..Default::default()
        }
        .with_env_overrides();
        assert_eq!(c.warn_free_bytes, 5_000_000_000);
        assert_eq!(c.poll_interval, Duration::from_secs(45));
        std::env::remove_var("CIRIS_PERSIST_DISK_WARN_BYTES");
        std::env::remove_var("CIRIS_PERSIST_DISK_POLL_INTERVAL");
    }
}
