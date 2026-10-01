//! v52.0.2 (CIRISServer#705, CIRISPersist#354) — a pool connection created
//! on a thread that has no persist tokio runtime.

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
        drop(backend);
        rt.shutdown_background();
    }
}
