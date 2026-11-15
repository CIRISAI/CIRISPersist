//! v62.0.0 (slice A, P5) — **the executor seam**: spawn, timers, and
//! blocking dispatch.
//!
//! FSD WASM_NODE §5.1: one thread, a cooperative executor (`ciris-rt`) inside
//! the module, storage synchronous in the tick, `spawn_blocking` inline.
//! Persist's node code spawns, sleeps, times out and dispatches blocking
//! work through this module only, so a host swaps the executor without a
//! `cfg(target_*)` anywhere in node code (§4.1 rule 2).
//!
//! # Profiles
//!
//! - **Native** (the default, nothing installed): every call is the tokio
//!   call v61 made — [`spawn`] is `tokio::spawn`, [`sleep`] is
//!   `tokio::time::sleep`, [`timeout`] is `tokio::time::timeout`, and
//!   [`dispatch_blocking`] hands the closure to the running runtime's
//!   blocking pool (inline when there is no runtime, CIRISPersist#158).
//! - **Single-thread** ([`TokioExecutor::single_thread`], or any host
//!   [`Executor`] whose [`Executor::blocking_runs_inline`] is true):
//!   blocking work runs inline on the calling task, so a current-thread
//!   runtime opens, writes and reads a store without ever starting a thread.
//! - **Host** (a `ciris-rt` executor): implements [`Executor`] over its own
//!   task queue and timer events.
//!
//! The seam is module-scoped, installed once by the host
//! ([`crate::host::HostSeams::install`]), for the same reason as the clock:
//! one module, one executor (FSD §5.1).
//!
//! # No runtime type is stored
//!
//! [`TokioExecutor`] holds no `Handle`; it reaches tokio through the
//! ambient thread-local exactly as `tokio::spawn` does. A foreign copy of
//! persist's code therefore never walks a runtime persist's `.so` laid out
//! (the CIRISPersist#1231 / #705 class).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use parking_lot::RwLock;

/// A boxed, sendable unit task.
pub type BoxTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Why a task ended without finishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskError {
    /// The task was aborted, or its executor shut down before it finished.
    Cancelled,
    /// The task panicked; the message when one could be read.
    Panicked(String),
}

impl std::fmt::Display for TaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "task cancelled"),
            Self::Panicked(m) => write!(f, "task panicked: {m}"),
        }
    }
}

impl std::error::Error for TaskError {}

/// A spawned task. Awaiting it yields how it ended; dropping it detaches
/// the task (it keeps running), as with tokio's `JoinHandle`.
pub struct TaskHandle {
    join: Pin<Box<dyn Future<Output = Result<(), TaskError>> + Send + 'static>>,
    abort: Box<dyn Fn() + Send + Sync + 'static>,
    finished: Box<dyn Fn() -> bool + Send + Sync + 'static>,
}

impl TaskHandle {
    /// A handle over a tokio `JoinHandle`.
    #[must_use]
    pub fn from_tokio(jh: tokio::task::JoinHandle<()>) -> Self {
        let abort = jh.abort_handle();
        let probe = jh.abort_handle();
        Self {
            join: Box::pin(async move {
                jh.await.map_err(|e| {
                    if e.is_panic() {
                        TaskError::Panicked(panic_message(e.into_panic().as_ref()))
                    } else {
                        TaskError::Cancelled
                    }
                })
            }),
            abort: Box::new(move || abort.abort()),
            finished: Box::new(move || probe.is_finished()),
        }
    }

    /// A handle a host executor builds from its own parts: the future that
    /// resolves when the task ends, how to abort it, and whether it has ended.
    pub fn from_parts(
        join: impl Future<Output = Result<(), TaskError>> + Send + 'static,
        abort: impl Fn() + Send + Sync + 'static,
        finished: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            join: Box::pin(join),
            abort: Box::new(abort),
            finished: Box::new(finished),
        }
    }

    /// Ask the task to stop at its next yield point.
    pub fn abort(&self) {
        (self.abort)();
    }

    /// True once the task has ended (finished, panicked or been aborted).
    #[must_use]
    pub fn is_finished(&self) -> bool {
        (self.finished)()
    }
}

impl std::fmt::Debug for TaskHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskHandle")
            .field("finished", &self.is_finished())
            .finish_non_exhaustive()
    }
}

impl Future for TaskHandle {
    type Output = Result<(), TaskError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.join.as_mut().poll(cx)
    }
}

/// The executor a host supplies.
pub trait Executor: Send + Sync + 'static {
    /// Start `task`; it runs until it finishes or is aborted.
    fn spawn(&self, task: BoxTask) -> TaskHandle;

    /// A future that resolves after `d`.
    fn sleep(&self, d: Duration) -> BoxTask;

    /// True when blocking work must run inline on the calling task (one
    /// thread, FSD §5.1). False hands it to a blocking pool.
    fn blocking_runs_inline(&self) -> bool;
}

/// How [`TokioExecutor`] dispatches blocking work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocking {
    /// The running runtime's blocking pool (inline with no runtime).
    Pool,
    /// Inline on the calling task, always.
    Inline,
}

/// The tokio-backed executor. [`TokioExecutor::native`] is what an
/// uninstalled seam behaves as; [`TokioExecutor::single_thread`] is the
/// single-thread profile on a current-thread runtime.
#[derive(Debug, Clone, Copy)]
pub struct TokioExecutor {
    blocking: Blocking,
}

impl TokioExecutor {
    /// Today's native behaviour: tokio spawn and timers, a blocking pool.
    #[must_use]
    pub const fn native() -> Self {
        Self {
            blocking: Blocking::Pool,
        }
    }

    /// The single-thread profile: tokio spawn and timers on whatever
    /// runtime polls the caller (a current-thread one, for one thread),
    /// and blocking work inline — no blocking-pool thread is ever started.
    #[must_use]
    pub const fn single_thread() -> Self {
        Self {
            blocking: Blocking::Inline,
        }
    }

    /// This executor's blocking mode.
    #[must_use]
    pub const fn blocking(&self) -> Blocking {
        self.blocking
    }
}

impl Executor for TokioExecutor {
    fn spawn(&self, task: BoxTask) -> TaskHandle {
        TaskHandle::from_tokio(tokio::spawn(task))
    }

    fn sleep(&self, d: Duration) -> BoxTask {
        Box::pin(tokio::time::sleep(d))
    }

    fn blocking_runs_inline(&self) -> bool {
        self.blocking == Blocking::Inline
    }
}

static INSTALLED: AtomicBool = AtomicBool::new(false);

fn slot() -> &'static RwLock<Option<Arc<dyn Executor>>> {
    static SLOT: OnceLock<RwLock<Option<Arc<dyn Executor>>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(None))
}

fn installed() -> Option<Arc<dyn Executor>> {
    if INSTALLED.load(Ordering::Acquire) {
        slot().read().as_ref().map(Arc::clone)
    } else {
        None
    }
}

/// Install `exec` as this module's executor. Returns the one it replaced.
pub fn install(exec: Arc<dyn Executor>) -> Option<Arc<dyn Executor>> {
    let prev = slot().write().replace(exec);
    INSTALLED.store(true, Ordering::Release);
    prev
}

/// Go back to the native default. Returns the executor that was installed.
pub fn uninstall() -> Option<Arc<dyn Executor>> {
    let prev = slot().write().take();
    INSTALLED.store(false, Ordering::Release);
    prev
}

/// True when blocking work runs inline (the single-thread profile).
#[must_use]
pub fn blocking_runs_inline() -> bool {
    installed().is_some_and(|e| e.blocking_runs_inline())
}

/// **Spawn a task** on the installed executor (`tokio::spawn` natively).
pub fn spawn<F>(task: F) -> TaskHandle
where
    F: Future<Output = ()> + Send + 'static,
{
    match installed() {
        Some(e) => e.spawn(Box::pin(task)),
        None => TaskHandle::from_tokio(tokio::spawn(task)),
    }
}

/// **Sleep** for `d` on the installed executor's timer
/// (`tokio::time::sleep` natively).
pub async fn sleep(d: Duration) {
    match installed() {
        Some(e) => e.sleep(d).await,
        None => tokio::time::sleep(d).await,
    }
}

/// The deadline of a [`timeout`] passed first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed;

impl std::fmt::Display for Elapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "deadline has elapsed")
    }
}

impl std::error::Error for Elapsed {}

/// **Run `f` with a deadline** (`tokio::time::timeout` natively). On a
/// host executor, `f` is polled first on every wake and the host's
/// [`Executor::sleep`] is the deadline.
///
/// # Errors
///
/// [`Elapsed`] when `d` passes before `f` resolves.
pub async fn timeout<F: Future>(d: Duration, f: F) -> Result<F::Output, Elapsed> {
    match installed() {
        Some(e) => {
            let deadline = e.sleep(d);
            tokio::select! {
                biased;
                v = f => Ok(v),
                () = deadline => Err(Elapsed),
            }
        }
        None => tokio::time::timeout(d, f).await.map_err(|_| Elapsed),
    }
}

/// **Run `f`, a blocking closure, without stalling the executor where it
/// can be moved, and inline where it cannot** (FSD §3.3, §5.1).
///
/// - Single-thread profile ([`blocking_runs_inline`]): `f` runs inline.
/// - Native: `f` goes to the running tokio runtime's blocking pool. With no
///   runtime on this thread (`Handle::try_current()` is the same
///   thread-local read `spawn_blocking` performs, but returns `Err` where
///   `spawn_blocking` panics), `f` runs inline: a cohabiting consumer's
///   statically linked copy of persist on a foreign worker takes the inline
///   arm, as v3.14.0 → v43.0.0 always did (CIRISPersist#158).
///
/// A panic inside `f` is re-raised on the caller (`resume_unwind`) so the
/// observable behaviour matches the inline arm. A join cancelled by
/// runtime shutdown has no value to return; it panics naming the cause, and
/// the caller's task is being torn down regardless.
pub async fn dispatch_blocking<R, F>(f: F) -> R
where
    R: Send + 'static,
    F: FnOnce() -> R + Send + 'static,
{
    if blocking_runs_inline() {
        return f();
    }
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.spawn_blocking(f).await {
            Ok(r) => r,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => panic!("blocking task cancelled by runtime shutdown: {e}"),
        },
        Err(_) => f(),
    }
}

/// The future [`try_dispatch_blocking`] returns: the closure's value, or how
/// the blocking task failed.
pub type BlockingTask<R> = Pin<Box<dyn Future<Output = Result<R, TaskError>> + Send + 'static>>;

fn panic_message(p: &(dyn std::any::Any + Send)) -> String {
    p.downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_default()
}

/// [`dispatch_blocking`] that reports a panicking or cancelled closure as a
/// [`TaskError`] instead of re-raising it: the replacement for a raw
/// `tokio::task::spawn_blocking(f).await`, whose `JoinError` the caller
/// maps into its own error type. Same dispatch rule: inline in the
/// single-thread profile and off-runtime, the blocking pool otherwise.
///
/// The closure starts when the returned future is first polled (every
/// caller awaits it at once).
pub fn try_dispatch_blocking<R, F>(f: F) -> BlockingTask<R>
where
    R: Send + 'static,
    F: FnOnce() -> R + Send + 'static,
{
    Box::pin(async move {
        let inline = |f: F| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
                .map_err(|p| TaskError::Panicked(panic_message(p.as_ref())))
        };
        if blocking_runs_inline() {
            return inline(f);
        }
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.spawn_blocking(f).await.map_err(|e| {
                if e.is_panic() {
                    TaskError::Panicked(panic_message(e.into_panic().as_ref()))
                } else {
                    TaskError::Cancelled
                }
            }),
            Err(_) => inline(f),
        }
    })
}
