//! v52.0.2 (CIRISServer#705, CIRISPersist#354) — a pool connection created
//! on a thread that has no persist tokio runtime.
//!
//! The persist and edge wheels each link their OWN tokio. Edge holds the
//! concrete backend and polls `pool.get()` on its runtime thread; a pool miss
//! calls the `Box<dyn Connect>` that persist's `.so` built, whose tokio-postgres
//! DNS/TCP and `tokio::spawn(connection)` run against PERSIST's tokio — which
//! has no runtime on that thread. "There is no reactor running" panicked there,
//! and across two `.so`s the panic aborted the process.
//!
//! [`PersistRuntimeConnect`] makes the decision INSIDE persist's code, where
//! `Handle::try_current()` asks persist's own tokio: with a persist runtime on
//! the thread it connects inline (the single-cdylib server, every pyo3 path);
//! without one it runs the connect on the handle captured when the backend was
//! built and awaits the `JoinHandle` (a waker, no reactor needed). The
//! connection driver is spawned there, on persist's runtime, where it must
//! live. A panic in the hop comes back as a `JoinError` — an error, never an
//! unwind across the boundary.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use deadpool_postgres::Connect;
use tokio::task::JoinHandle;

/// Connections this process created by hopping onto persist's runtime.
pub(crate) static HOPS: AtomicUsize = AtomicUsize::new(0);

type ConnectFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<(tokio_postgres::Client, JoinHandle<()>), tokio_postgres::Error>,
            > + Send
            + 'a,
    >,
>;

/// The pool's connector: deadpool's own, run on persist's runtime when the
/// polling thread has none of persist's.
pub(crate) struct PersistRuntimeConnect<C> {
    inner: Arc<C>,
    rt: Option<tokio::runtime::Handle>,
}

impl<C> PersistRuntimeConnect<C> {
    /// Capture persist's runtime from the constructing thread — the backend's
    /// `connect`, which runs on it.
    pub(crate) fn new(inner: C) -> Self {
        Self {
            inner: Arc::new(inner),
            rt: tokio::runtime::Handle::try_current().ok(),
        }
    }
}

impl<C: Connect + 'static> Connect for PersistRuntimeConnect<C> {
    fn connect(&self, pg_config: &tokio_postgres::Config) -> ConnectFuture<'_> {
        let inner = self.inner.clone();
        let rt = self.rt.clone();
        let cfg = pg_config.clone();
        Box::pin(async move {
            match (tokio::runtime::Handle::try_current(), rt) {
                (Err(_), Some(rt)) => {
                    HOPS.fetch_add(1, Ordering::Relaxed);
                    match rt.spawn(async move { inner.connect(&cfg).await }).await {
                        Ok(connected) => connected,
                        Err(join) => Err(hop_failed(&join)),
                    }
                }
                _ => inner.connect(&cfg).await,
            }
        })
    }
}

/// A hop that did not return a connection (the task panicked, or persist's
/// runtime is shutting down). `tokio_postgres::Error` has no public
/// constructor, so this returns the one error a caller can build — a config
/// parse refusal whose cause (in its `Debug` form) names this failure; the
/// join error itself is logged.
fn hop_failed(join: &tokio::task::JoinError) -> tokio_postgres::Error {
    tracing::error!(
        error = %join,
        "ciris-persist: pool connect on persist's runtime did not complete (CIRISServer#705)"
    );
    "ciris_persist_runtime_hop_failed=1"
        .parse::<tokio_postgres::Config>()
        .expect_err("an unknown option never parses")
}

/// v61.1.0 (CIRISPersist#1231): persist's runtime, reached only through a
/// vtable that persist's `.so` wrote.
///
/// Until v61.0.5 the backend kept a raw `tokio::runtime::Handle` for its
/// checkout timer. `checkout_bounded` is monomorphic code, so a consumer that
/// links persist as an rlib (Edge) compiles its OWN copy of it against its OWN
/// tokio. When that copy ran on a thread with none of its tokio (persist's
/// executor worker polling an Edge future), it called `rt.spawn(...)` on
/// the persist-built `Handle`: Edge's tokio walking another tokio's layout,
/// a SIGSEGV inside `OwnedTasks`. Marking a function `#[inline(never)]` or
/// non-generic does not fix this. The foreign crate compiles its own copy of
/// every such function, so only a pointer written at construction time
/// leads back into persist's code.
///
/// The backend therefore holds an `Arc<dyn PersistRuntimeTimer>` that
/// [`capture_persist_timer`] builds where the backend is built. Every call
/// through it, and the `poll` and `drop` of the future it returns, run the
/// code at the vtable persist's `.so` wrote. That code runs on persist's
/// tokio, against the `Handle` that same tokio built. The fix for #705
/// ([`PersistRuntimeConnect`], reached as deadpool's `Box<dyn Connect>`) has
/// the same shape.
pub(crate) trait PersistRuntimeTimer: Send + Sync {
    /// A future that completes once `wait` has elapsed on persist's runtime.
    /// It also completes early if persist's runtime stops the timer (the
    /// runtime shutting down). Dropping it before then cancels the timer
    /// task.
    fn sleep(&self, wait: std::time::Duration) -> TimerFuture;
}

/// The future a [`PersistRuntimeTimer`] hands back. It is boxed so that its
/// `poll` and `drop` are entries in the vtable the timer's own code wrote.
pub(crate) type TimerFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;

/// What [`super::postgres::PostgresBackend`] holds instead of a `Handle`.
pub(crate) type PersistTimer = Arc<dyn PersistRuntimeTimer>;

/// Timers this process started on persist's runtime through a
/// [`PersistRuntimeTimer`]. The I1550-series witnesses read it, and nothing
/// else does, so it exists only in test builds.
#[cfg(test)]
pub(crate) static TIMER_STARTS: AtomicUsize = AtomicUsize::new(0);

/// The one [`PersistRuntimeTimer`]: the runtime captured on the
/// constructing thread. Its `Handle` is never read from outside this impl.
struct CapturedRuntime {
    rt: tokio::runtime::Handle,
}

/// Aborts the timer task when the [`TimerFuture`] holding it is dropped.
/// A checkout that wins the race must not leave a sleeping task on
/// persist's runtime for the rest of the wait.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl PersistRuntimeTimer for CapturedRuntime {
    fn sleep(&self, wait: std::time::Duration) -> TimerFuture {
        #[cfg(test)]
        TIMER_STARTS.fetch_add(1, Ordering::Relaxed);
        // The `Sleep` is built INSIDE the task. Building it here would ask
        // the polling thread for a timer it does not have.
        let task = AbortOnDrop(self.rt.spawn(async move { tokio::time::sleep(wait).await }));
        Box::pin(async move {
            let mut task = task;
            // A `JoinError` (cancelled by runtime shutdown) also ends the
            // wait: nothing is left to time it.
            let _ = (&mut task.0).await;
        })
    }
}

/// The timer a backend keeps: persist's runtime on the constructing thread,
/// or `None` when that thread has no runtime (then nothing can run a timer).
pub(crate) fn capture_persist_timer() -> Option<PersistTimer> {
    tokio::runtime::Handle::try_current()
        .ok()
        .map(|rt| Arc::new(CapturedRuntime { rt }) as PersistTimer)
}

/// v61.1.0 (CIRISPersist#1231): a pause on the checkout path that never
/// asks a thread for a reactor it lacks. On a thread with a runtime of the
/// running copy's tokio it is `tokio::time::sleep`. Otherwise it goes
/// through persist's timer, or returns at once when there is none (no
/// runtime anywhere can time it). `get_client`'s retry backoff used to call
/// `tokio::time::sleep` directly, which panicked off-runtime ("no reactor
/// running").
pub(crate) async fn pause(wait: std::time::Duration, timer: Option<&dyn PersistRuntimeTimer>) {
    match (tokio::runtime::Handle::try_current(), timer) {
        (Ok(_), _) => tokio::time::sleep(wait).await,
        (Err(_), Some(timer)) => timer.sleep(wait).await,
        (Err(_), None) => {}
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake};

    /// Poll `f` to completion on THIS thread with no tokio runtime at all —
    /// what a foreign tokio copy's thread looks like to persist's tokio.
    pub(super) fn block_on_no_runtime<F: Future>(f: F) -> F::Output {
        struct Unpark(std::thread::Thread);
        impl Wake for Unpark {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
        }
        let waker = Arc::new(Unpark(std::thread::current())).into();
        let mut cx = Context::from_waker(&waker);
        let mut f = std::pin::pin!(f);
        loop {
            match f.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::park(),
            }
        }
    }

    /// I320 — a backend built inside persist's runtime hands a NEW pool
    /// connection to a caller polling from a thread with no persist runtime
    /// (edge's transport thread, which runs a second tokio copy). Before
    /// v52.0.2 the connect ran tokio-postgres' DNS/TCP and `tokio::spawn`
    /// against persist's tokio with no reactor: "there is no reactor running",
    /// and across two `.so`s the panic aborted the process.
    #[test]
    fn i320_a_thread_without_persist_runtime_gets_a_new_connection() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("persist runtime");
        let backend = Arc::new(
            rt.block_on(crate::store::postgres::PostgresBackend::connect(&dsn))
                .expect("connect"),
        );
        let b = backend.clone();
        let joined = std::thread::spawn(move || {
            block_on_no_runtime(async move {
                let client = b.get_client().await.map_err(|e| e.to_string())?;
                let row = client
                    .query_one("SELECT 1::INT4", &[])
                    .await
                    .map_err(|e| e.to_string())?;
                Ok::<i32, String>(row.get(0))
            })
        })
        .join();
        assert!(
            matches!(joined, Ok(Ok(1))),
            "I320: a foreign thread must get a working connection, not a panic: {:?}",
            joined.as_ref().map_err(|p| p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_owned())))
        );
        assert!(
            super::HOPS.load(std::sync::atomic::Ordering::Relaxed) >= 1,
            "I320: the connection was created by a hop onto persist's runtime"
        );
        drop(backend);
        rt.shutdown_background();
    }

    /// v59.1.2 (I320c) — the checkout's wait bound holds on a thread with no
    /// persist runtime. deadpool's own wait timer panicked there ("no reactor
    /// running"), so the bound runs its timer on persist's runtime: a starved
    /// pool polled from a foreign thread is `PoolExhausted` within the wait,
    /// not a panic and not a hang.
    #[test]
    fn i320c_a_starved_pool_is_typed_on_a_thread_without_persist_runtime() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("persist runtime");
        let wait = std::time::Duration::from_secs(2);
        let backend = Arc::new(
            rt.block_on(
                crate::store::postgres::PostgresBackend::connect_with_pool_for_test(&dsn, 1, wait),
            )
            .expect("connect"),
        );
        let held = rt
            .block_on(backend.get_client())
            .expect("the only connection");
        let b = backend.clone();
        let started = std::time::Instant::now();
        let joined = std::thread::spawn(move || {
            block_on_no_runtime(async move { b.get_client().await.map(|_| ()) })
        })
        .join();
        match joined {
            Ok(Err(crate::store::Error::PoolExhausted { waited })) => assert_eq!(waited, wait),
            other => panic!(
                "I320c: a typed exhaustion, not {:?}",
                other.map(|r| r.err())
            ),
        }
        assert!(
            started.elapsed() < wait * 3,
            "I320c: {:?}",
            started.elapsed()
        );
        drop(held);
        drop(backend);
        rt.shutdown_background();
    }

    /// I320b — a connect that PANICS on persist's runtime comes back to a
    /// thread without one as an ERROR. Across two `.so`s an unwind there is
    /// the abort; a `JoinError` must never be re-raised.
    #[test]
    fn i320b_a_panicking_connect_is_an_error_not_an_unwind() {
        struct Panics;
        impl deadpool_postgres::Connect for Panics {
            fn connect(&self, _: &tokio_postgres::Config) -> super::ConnectFuture<'_> {
                Box::pin(async { panic!("connect panicked on persist's runtime") })
            }
        }
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("persist runtime");
        let wrapped = Arc::new(rt.block_on(async { super::PersistRuntimeConnect::new(Panics) }));
        let joined = std::thread::spawn(move || {
            let cfg = tokio_postgres::Config::new();
            block_on_no_runtime(async move {
                deadpool_postgres::Connect::connect(&*wrapped, &cfg)
                    .await
                    .map(|_| ())
                    .map_err(|e| format!("{e:?}"))
            })
        })
        .join();
        match joined {
            Ok(Err(e)) => assert!(e.contains("ciris_persist_runtime_hop_failed"), "{e}"),
            other => panic!(
                "I320b: expected an error, got {:?}",
                other.map(|r| r.is_ok())
            ),
        }
        rt.shutdown_background();
    }

    /// I321 — with persist's runtime on the polling thread (the server's one
    /// cdylib, every pyo3 path) the connector connects INLINE: no hop.
    #[test]
    fn i321_a_thread_with_persist_runtime_connects_inline() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("persist runtime");
        let before = super::HOPS.load(std::sync::atomic::Ordering::Relaxed);
        let one: i32 = rt.block_on(async {
            let backend = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .expect("connect");
            let client = backend.get_client().await.expect("client");
            client
                .query_one("SELECT 1::INT4", &[])
                .await
                .expect("query")
                .get(0)
        });
        assert_eq!(one, 1);
        assert_eq!(
            super::HOPS.load(std::sync::atomic::Ordering::Relaxed),
            before,
            "I321: a thread with persist's runtime never hops"
        );
        rt.shutdown_background();
    }

    /// The hop-failure error is a real `tokio_postgres::Error` naming the
    /// failure — the only constructor a caller has.
    #[test]
    fn a_failed_hop_is_an_error_naming_itself() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("rt");
        let join = rt
            .block_on(async { tokio::spawn(async { panic!("boom") }).await })
            .expect_err("the task panicked");
        let e = super::hop_failed(&join);
        assert!(
            format!("{e:?}").contains("ciris_persist_runtime_hop_failed"),
            "{e:?}"
        );
    }
}
