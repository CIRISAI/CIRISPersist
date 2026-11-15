//! v62.0.0 (slice A) — **the host seams.** What a host gives the node, in one
//! place: time ([`clock`]), the executor ([`rt`]) and lifecycle events
//! ([`lifecycle`]).
//!
//! FSD WASM_NODE §4.1: node code holds no `cfg(target_*)`; host differences
//! are runtime answers. §5.1: one thread, every source of non-determinism an
//! import. Persist's node code reads time, spawns, sleeps and dispatches
//! blocking work only through these modules, so the same source runs on a
//! native tokio host, a browser Worker and the EFI shim.
//!
//! A host builds a [`HostSeams`] and calls [`HostSeams::install`] once,
//! before it builds an Engine or a store; every Engine and store built after
//! reads the installed seams. Nothing installed is the native default
//! ([`HostSeams::native`]), byte-for-byte the behaviour of v61.

pub mod clock;
pub mod lifecycle;
pub mod rt;

use std::sync::Arc;

pub use clock::{Clock, FixedClock, Instant, SystemClock};
pub use lifecycle::{Lifecycle, LifecycleEvent, LifecycleState};
pub use rt::{Executor, TaskError, TaskHandle, TokioExecutor};

/// The seams one host supplies.
#[derive(Clone)]
pub struct HostSeams {
    /// Wall and monotonic time.
    pub clock: Arc<dyn Clock>,
    /// Spawn, timers, blocking dispatch.
    pub executor: Arc<dyn Executor>,
}

impl std::fmt::Debug for HostSeams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostSeams")
            .field(
                "blocking_runs_inline",
                &self.executor.blocking_runs_inline(),
            )
            .finish_non_exhaustive()
    }
}

impl HostSeams {
    /// The native host: the system clock, tokio with a blocking pool.
    #[must_use]
    pub fn native() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            executor: Arc::new(TokioExecutor::native()),
        }
    }

    /// The single-thread profile: the system clock, tokio on whatever runtime
    /// polls the caller, blocking work inline (FSD §5.1).
    #[must_use]
    pub fn single_thread() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            executor: Arc::new(TokioExecutor::single_thread()),
        }
    }

    /// These seams with `clock` in place of theirs.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// These seams with `executor` in place of theirs.
    #[must_use]
    pub fn with_executor(mut self, executor: Arc<dyn Executor>) -> Self {
        self.executor = executor;
        self
    }

    /// **Install these seams for this module.** Call once, before building
    /// an Engine or a store.
    pub fn install(self) {
        clock::install(self.clock);
        rt::install(self.executor);
    }
}
