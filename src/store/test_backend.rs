//! v60.0.0 (CIRISPersist#1002) — **the one backend constructor for tests.**
//!
//! `MemoryBackend` is retired. Every test that ran on it runs on
//! [`SqliteBackend`] in memory with every migration applied: real SQL, a real
//! schema and real transaction semantics, which is where the reds the memory
//! backend could not produce come from.
//!
//! Measured on this box (#1002 step 1, `measure` below): `MemoryBackend::new()`
//! took 90 µs and `SqliteBackend::open_in_memory()` + `run_migrations()` took
//! 248 ms, so replay dominates. One migrated database per process is the
//! TEMPLATE; each [`test_backend`] clones it with the SQLite backup API and then
//! runs the real open path ([`Backend::run_migrations`]), which finds every
//! migration applied and runs the open-time passes over an empty store, so a
//! clone is a backend in exactly the state a fresh migrated one is.
//!
//! Synchronous on purpose: it replaces a synchronous constructor at every call
//! site, inside async tests and outside them. The open path runs on a scoped
//! thread with its own current-thread runtime, so it never blocks on, or
//! needs, the caller's runtime.

use std::sync::{Arc, OnceLock};

use crate::store::sqlite::SqliteBackend;
use crate::store::Backend as _;

type Conn = Arc<parking_lot::Mutex<rusqlite::Connection>>;

static TEMPLATE: OnceLock<Conn> = OnceLock::new();

/// Run `f`'s future to completion on a fresh current-thread runtime on its own
/// thread (no runtime context there, so the sqlite dispatcher runs inline).
fn on_own_runtime<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|s| {
        s.spawn(f)
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e))
    })
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test_backend: a current-thread runtime")
        .block_on(fut)
}

fn template() -> &'static Conn {
    TEMPLATE.get_or_init(|| {
        on_own_runtime(|| {
            block_on(async {
                let b = SqliteBackend::open_in_memory()
                    .await
                    .expect("test_backend template: open");
                b.run_migrations()
                    .await
                    .expect("test_backend template: migrate");
                b.conn_handle()
            })
        })
    })
}

/// A fresh, empty, fully migrated in-memory [`SqliteBackend`]: one per call,
/// sharing nothing with any other. The test constructor (#1002).
pub fn test_backend() -> SqliteBackend {
    let mut dst = rusqlite::Connection::open_in_memory().expect("test_backend: open the clone");
    {
        let src = template().lock();
        let backup =
            rusqlite::backup::Backup::new(&src, &mut dst).expect("test_backend: backup handle");
        backup
            .step(-1)
            .expect("test_backend: copy the migrated template");
    }
    let dst = SqliteBackend::apply_connection_settings(dst).expect("test_backend: pragmas");
    let backend = SqliteBackend::from_handles(
        Arc::new(parking_lot::Mutex::new(dst)),
        crate::store::sqlite_conn_model::ReadPool::empty(),
    );
    on_own_runtime(|| {
        block_on(backend.run_migrations()).expect("test_backend: the open path over the clone");
    });
    backend
}

#[cfg(test)]
mod measure {
    use crate::store::Backend as _;
    use std::time::Instant;

    /// #1002 step 1 — `open_in_memory()` + every migration, against
    /// `MemoryBackend::new()` and the template clone. Run with
    /// `--run-ignored only --no-capture`.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn measure_open_in_memory_against_memory_backend() {
        let n_mem = 500u32;
        let t = Instant::now();
        for _ in 0..n_mem {
            let b = crate::store::memory::MemoryBackend::new();
            std::hint::black_box(&b);
        }
        let mem = t.elapsed() / n_mem;

        let n = 30u32;
        let t = Instant::now();
        for _ in 0..n {
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            std::hint::black_box(&b);
        }
        let open = t.elapsed() / n;

        let t = Instant::now();
        for _ in 0..n {
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
        }
        let migrated = t.elapsed() / n;

        let _ = super::test_backend(); // the template, built once
        let n_t = 200u32;
        let t = Instant::now();
        for _ in 0..n_t {
            std::hint::black_box(super::test_backend());
        }
        let cloned = t.elapsed() / n_t;
        println!(
            "#1002 MEASURE MemoryBackend::new {mem:?} | open_in_memory {open:?} | \
             open_in_memory+run_migrations {migrated:?} | test_backend (template clone + open path) {cloned:?}"
        );
    }

    /// The clone is a migrated, empty backend that serves a door.
    #[tokio::test]
    async fn the_clone_is_migrated_and_independent() {
        let a = super::test_backend();
        let b = super::test_backend();
        a.conn_handle()
            .lock()
            .execute_batch("CREATE TABLE s5_probe(x INTEGER)")
            .unwrap();
        let has = |be: &crate::store::sqlite::SqliteBackend| -> bool {
            be.conn_handle()
                .lock()
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name = 's5_probe'",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap()
                == 1
        };
        assert!(has(&a) && !has(&b), "clones share nothing");
        assert!(
            crate::federation::FederationDirectory::lookup_public_key(&a, "nobody")
                .await
                .unwrap()
                .is_none()
        );
    }
}
