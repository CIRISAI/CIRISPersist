//! v62.0.0 (slice A, P3) — **the clock seam.** Every production read of wall
//! or monotonic time in persist's node code goes through here.
//!
//! FSD WASM_NODE §4.4 / §5.1: time is an import. A node module running in a
//! browser Worker or under the EFI shim has no `SystemTime`, no
//! `std::time::Instant` (both panic on `wasm32-unknown-unknown`) and no
//! chrono `Date` binding (a JS import, which §4.1 rule 1 forbids). The host
//! answers `ciris.now_us`; persist reads it through one [`Clock`].
//!
//! # The shape
//!
//! - [`Clock`] — the trait a host implements: [`Clock::now`] is the wall
//!   instant, as persist's existing instant type (`DateTime<Utc>`), and
//!   [`Clock::monotonic`] is an opaque, never-decreasing reading.
//! - [`SystemClock`] — the native default. `now()` reads the OS wall clock `chrono::Utc::now()` reads,
//!   so a native node stamps the same instants it always did: the signed
//!   instants, and the µs truncation every store applies when it writes one,
//!   are untouched (the truncation lives in the stores' formatters, which
//!   this seam does not reach).
//! - [`FixedClock`] — a clock a test or a deterministic replay sets by hand.
//! - [`Instant`] — persist's monotonic instant, a drop-in for the slice of
//!   `std::time::Instant` the node uses (`elapsed`, `duration_since`,
//!   `+ Duration`, ordering).
//! - [`now`] / [`monotonic_now`] — the reads every node site makes.
//!
//! # Why the clock is module-scoped, not threaded per handle
//!
//! The clock is installed once per module, by the host, before it builds an
//! Engine or a store ([`crate::host::HostSeams::install`]), and every Engine
//! and store built afterwards reads it. That is the FSD's model exactly: a
//! WASM node is one module with one `ciris.now_us` import, and §5.1's replay
//! records time at that one boundary. Threading an `Arc<dyn Clock>` through
//! every door instead would touch about 300 free functions whose `now` the
//! kernel slice (P14) turns into one kernel argument anyway.
//!
//! Nothing installed means [`SystemClock`], read without a lock (one relaxed
//! atomic load), so a native process that never calls `install` pays nothing
//! and behaves byte-for-byte as v61 did.
//!
//! # A foreign copy reads its own slot
//!
//! A consumer that links persist as an rlib carries its own copy of this
//! module and its own statics. A clock persist's `.so` installed is never
//! walked by the consumer's copy, which falls back to its own
//! [`SystemClock`] (the #1231 class cannot arise: no runtime type is stored).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;

/// A source of wall and monotonic time, supplied by the host.
///
/// Implementations must be cheap: [`now`] is read on every stamp.
pub trait Clock: Send + Sync + 'static {
    /// The wall-clock instant now.
    fn now(&self) -> DateTime<Utc>;

    /// A monotonic reading: never decreases between two calls on one clock.
    /// Its origin is the clock's own and means nothing; only differences
    /// between two readings do (the contract of `std::time::Instant`).
    fn monotonic(&self) -> Duration;
}

/// The native default: the operating system's clocks.
///
/// `now()` is the OS wall clock (`chrono::Utc::now()`'s reading) and `monotonic()` is a
/// `std::time::Instant` measured from a process-wide origin, so every
/// reading on a native node is the reading v61 made.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

/// [`SystemClock`]'s monotonic readings start here, not at zero, so an
/// `Instant` a caller backdates (`monotonic_now() - ttl`) early in a process
/// stays representable, as it is with `std::time::Instant` (whose origin is
/// boot). About 34 years.
const SYSTEM_MONOTONIC_BASE: Duration = Duration::from_secs(1 << 30);

fn process_origin() -> std::time::Instant {
    static ORIGIN: OnceLock<std::time::Instant> = OnceLock::new();
    *ORIGIN.get_or_init(std::time::Instant::now)
}

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        // v62.0.0 (slice D) — the OS wall clock through `std::time`, which is
        // what `chrono::Utc::now()` reads on every native target (same
        // instant, same nanoseconds). Not `Utc::now()` itself: with chrono's
        // `wasmbind` on (rusqlite and verify-core turn it on for wasm32), that
        // call links a JS `Date` import into a node module even when the node
        // installs its own clock. A node never reads this clock.
        DateTime::<Utc>::from(std::time::SystemTime::now())
    }

    fn monotonic(&self) -> Duration {
        SYSTEM_MONOTONIC_BASE + process_origin().elapsed()
    }
}

/// A clock set by hand: wall time stays where it was put until
/// [`FixedClock::set`] or [`FixedClock::advance`] moves it, and the
/// monotonic reading moves with every `advance`.
///
/// For deterministic tests and replay (FSD §5.1). A host that wants real
/// time implements [`Clock`] over its own import instead.
#[derive(Debug)]
pub struct FixedClock {
    state: parking_lot::Mutex<(DateTime<Utc>, Duration)>,
}

impl FixedClock {
    /// A clock reading `at`, with its monotonic reading at
    /// [`SystemClock`]'s base.
    #[must_use]
    pub fn new(at: DateTime<Utc>) -> Self {
        Self {
            state: parking_lot::Mutex::new((at, SYSTEM_MONOTONIC_BASE)),
        }
    }

    /// Put the wall clock at `at`. The monotonic reading does not move:
    /// wall time can step, monotonic time cannot go back.
    pub fn set(&self, at: DateTime<Utc>) {
        self.state.lock().0 = at;
    }

    /// Move both readings forward by `by`.
    pub fn advance(&self, by: Duration) {
        let mut s = self.state.lock();
        s.0 += chrono::Duration::from_std(by).unwrap_or(chrono::Duration::MAX);
        s.1 += by;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.state.lock().0
    }

    fn monotonic(&self) -> Duration {
        self.state.lock().1
    }
}

static INSTALLED: AtomicBool = AtomicBool::new(false);

fn slot() -> &'static RwLock<Option<Arc<dyn Clock>>> {
    static SLOT: OnceLock<RwLock<Option<Arc<dyn Clock>>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(None))
}

/// Install `clock` as this module's clock; every later read takes it.
/// Returns the clock it replaced (`None` when that was the default).
///
/// A host calls this once, before it builds an Engine or a store
/// ([`crate::host::HostSeams::install`] does it for the whole seam set).
pub fn install(clock: Arc<dyn Clock>) -> Option<Arc<dyn Clock>> {
    let prev = slot().write().replace(clock);
    INSTALLED.store(true, Ordering::Release);
    prev
}

/// Go back to [`SystemClock`]. Returns the clock that was installed.
pub fn uninstall() -> Option<Arc<dyn Clock>> {
    let prev = slot().write().take();
    INSTALLED.store(false, Ordering::Release);
    prev
}

/// The installed clock, or [`SystemClock`] when none is.
#[must_use]
pub fn current() -> Arc<dyn Clock> {
    if INSTALLED.load(Ordering::Acquire) {
        if let Some(c) = slot().read().as_ref() {
            return Arc::clone(c);
        }
    }
    Arc::new(SystemClock)
}

/// **The wall-clock read.** Every production stamp in persist's node code
/// is this call: the installed clock's [`Clock::now`], or [`SystemClock`]'s
/// reading (the OS wall clock `chrono::Utc::now()` reads) when no clock is
/// installed.
///
/// v62.0.0 (slice D): the fallback is `SystemClock`, not `Utc::now()` itself:
/// on wasm32 with chrono's `wasmbind` on, `Utc::now()` links a JS `Date`
/// import into the node module (measured: `js_sys::Date::new_0` /
/// `get_time`, called only from here), and the import gate refuses it.
#[must_use]
#[inline]
pub fn now() -> DateTime<Utc> {
    if INSTALLED.load(Ordering::Acquire) {
        if let Some(c) = slot().read().as_ref() {
            return c.now();
        }
    }
    SystemClock.now()
}

/// **The monotonic read**: the installed clock's [`Clock::monotonic`] as an
/// [`Instant`]. Every production `std::time::Instant::now()` in node code is
/// this call.
#[must_use]
#[inline]
pub fn monotonic_now() -> Instant {
    if INSTALLED.load(Ordering::Acquire) {
        if let Some(c) = slot().read().as_ref() {
            return Instant(c.monotonic());
        }
    }
    Instant(SystemClock.monotonic())
}

/// Persist's monotonic instant: a reading of the installed clock's
/// [`Clock::monotonic`], taken by [`monotonic_now`]. Replaces `std::time::Instant` in node code, which
/// panics on `wasm32-unknown-unknown`.
///
/// Arithmetic saturates rather than panicking: an `Instant` minus more than
/// its reading is the clock's origin, and `duration_since` a later instant
/// is zero (std's `saturating_duration_since`, which std's own
/// `duration_since` has also done since Rust 1.60).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(Duration);

impl Instant {
    /// Time since `earlier`; zero when `earlier` is later.
    #[must_use]
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        self.0.saturating_sub(earlier.0)
    }

    /// Same as [`Self::duration_since`] (kept for the std spelling).
    #[must_use]
    pub fn saturating_duration_since(&self, earlier: Instant) -> Duration {
        self.duration_since(earlier)
    }

    /// `Some(self - earlier)`, or `None` when `earlier` is later.
    #[must_use]
    pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        self.0.checked_sub(earlier.0)
    }

    /// Time since this instant, on the installed clock.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        monotonic_now().duration_since(*self)
    }

    /// `Some(self + d)`, or `None` on overflow.
    #[must_use]
    pub fn checked_add(&self, d: Duration) -> Option<Instant> {
        self.0.checked_add(d).map(Instant)
    }

    /// `Some(self - d)`, or `None` below the clock's origin.
    #[must_use]
    pub fn checked_sub(&self, d: Duration) -> Option<Instant> {
        self.0.checked_sub(d).map(Instant)
    }
}

impl std::ops::Add<Duration> for Instant {
    type Output = Instant;
    fn add(self, d: Duration) -> Instant {
        Instant(self.0.saturating_add(d))
    }
}

impl std::ops::AddAssign<Duration> for Instant {
    fn add_assign(&mut self, d: Duration) {
        self.0 = self.0.saturating_add(d);
    }
}

impl std::ops::Sub<Duration> for Instant {
    type Output = Instant;
    fn sub(self, d: Duration) -> Instant {
        Instant(self.0.saturating_sub(d))
    }
}

impl std::ops::Sub<Instant> for Instant {
    type Output = Duration;
    fn sub(self, earlier: Instant) -> Duration {
        self.duration_since(earlier)
    }
}
