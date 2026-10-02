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
