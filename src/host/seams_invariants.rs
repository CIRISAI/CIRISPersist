//! v62.0.0 (slice A, host seams) — I1790–I1793, I1797–I1799: the seams carry
//! what a host gives the node.
//!
//! Every witness here installs seams into the module's slots. nextest runs
//! each test in its own process, so an installed clock or executor never
//! leaks into another test; each witness still uninstalls on the way out.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};

use super::clock::{self, FixedClock};
use super::rt::{self, TaskError, TokioExecutor};
use super::{HostSeams, Lifecycle, LifecycleEvent};

/// An instant every store keeps exactly: whole milliseconds, so the
/// substrate truncations (ms for a signed `valid_from`, µs for a stamp) are
/// both the identity on it. Far from any wall clock this suite runs at.
fn fixed_instant() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2031, 4, 5, 6, 7, 8).unwrap() + chrono::Duration::milliseconds(123)
}

/// Threads this process runs now, where the OS says (`/proc`); `None`
/// elsewhere. The portable count is the runtime's `on_thread_start`.
fn os_threads() -> Option<usize> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|v| v.trim().parse().ok())
}

/// A current-thread runtime that counts every thread it starts (blocking
/// pool threads included: tokio calls `on_thread_start` for each).
fn counting_current_thread() -> (tokio::runtime::Runtime, Arc<AtomicUsize>) {
    let started = Arc::new(AtomicUsize::new(0));
    let counter = started.clone();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .on_thread_start(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        })
        .build()
        .expect("current-thread runtime");
    (rt, started)
}

// ── I1790: a fixed Clock makes the Engine stamp exactly that instant ──────

/// **I1790.** With a [`FixedClock`] installed, the Engine's self-registration
/// stamps the record with exactly that instant: `valid_from` (the signed
/// instant) and `scrub_timestamp` (the stamp), read back from the store.
/// Run on both backends.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
async fn i1790_engine_stamps_the_installed_clock(dsn: &str, backend: &str) {
    use crate::federation::FederationDirectory as _;
    let at = fixed_instant();
    let signer = crate::federation::tier_ingest::test_support::local_signer(&format!(
        "i1790-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let engine = crate::Engine::with_signer(signer, dsn)
        .await
        .unwrap_or_else(|e| panic!("I1790 {backend}: engine: {e}"));
    // Installed after boot: the boot legs read the clock too, and the baked
    // trust root's windows are not this witness's subject.
    clock::install(Arc::new(FixedClock::new(at)));
    let kid = engine
        .register_self_federation_key("agent", "i1790", None, serde_json::json!({}), vec![])
        .await
        .unwrap_or_else(|e| panic!("I1790 {backend}: register_self: {e}"));
    let rec = match engine.backend() {
        #[cfg(feature = "sqlite")]
        crate::engine::BackendDispatch::Sqlite(b) => b.lookup_public_key(&kid).await,
        #[cfg(feature = "postgres")]
        crate::engine::BackendDispatch::Postgres(b) => b.lookup_public_key(&kid).await,
    }
    .unwrap_or_else(|e| panic!("I1790 {backend}: lookup: {e}"))
    .unwrap_or_else(|| panic!("I1790 {backend}: the registered key must be stored"));
    clock::uninstall();
    assert_eq!(
        rec.valid_from, at,
        "I1790 {backend}: the signed valid_from must be the installed clock's instant"
    );
    assert_eq!(
        rec.scrub_timestamp, at,
        "I1790 {backend}: the scrub stamp must be the installed clock's instant"
    );
    assert!(
        (Utc::now() - at).num_days() > 30 || (at - Utc::now()).num_days() > 30,
        "I1790: the fixed instant must be far from the wall clock, or a system-clock read passes"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn i1790_engine_stamps_the_installed_clock_sqlite() {
    i1790_engine_stamps_the_installed_clock("sqlite::memory:", "sqlite").await;
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn i1790_engine_stamps_the_installed_clock_postgres() {
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("I1790 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
        return;
    };
    i1790_engine_stamps_the_installed_clock(&dsn, "postgres").await;
    eprintln!("I1790 postgres: RAN");
}

// ── I1791: the clock reads ────────────────────────────────────────────────

/// **I1791.** `clock::now()` and `clock::monotonic_now()` read the installed
/// clock and only it: wall time stays put until set, monotonic time moves
/// exactly by `advance` (and not by `set`), and `uninstall` restores the
/// system clock.
#[test]
fn i1791_the_clock_reads_the_installed_clock() {
    let at = fixed_instant();
    let fixed = Arc::new(FixedClock::new(at));
    clock::install(fixed.clone());
    let m0 = clock::monotonic_now();
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(clock::now(), at, "I1791: wall time must not move by itself");
    assert_eq!(
        clock::monotonic_now(),
        m0,
        "I1791: monotonic time must not move by itself"
    );
    fixed.advance(Duration::from_secs(90));
    assert_eq!(clock::now(), at + chrono::Duration::seconds(90));
    assert_eq!(
        clock::monotonic_now().duration_since(m0),
        Duration::from_secs(90)
    );
    assert_eq!(
        m0.elapsed(),
        Duration::from_secs(90),
        "I1791: elapsed reads the seam"
    );
    fixed.set(at);
    assert_eq!(clock::now(), at);
    assert_eq!(
        clock::monotonic_now().duration_since(m0),
        Duration::from_secs(90),
        "I1791: stepping wall time must not step monotonic time"
    );
    clock::uninstall();
    let sys = clock::now();
    assert!(
        (sys - Utc::now()).num_seconds().abs() < 5,
        "I1791: uninstall restores the system clock"
    );
}

// ── I1792: one thread, open → write → read ─────────────────────────────────

#[cfg(feature = "sqlite")]
async fn open_write_read() {
    use crate::store::Backend as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("i1792.db");
    let backend = crate::store::sqlite::SqliteBackend::open(path.to_string_lossy().to_string())
        .await
        .expect("open");
    backend.run_migrations().await.expect("migrate");
    crate::federation::tier_ingest::test_support::register_hybrid_key(&backend, "i1792-key").await;
    let got = crate::federation::FederationDirectory::lookup_public_key(&backend, "i1792-key")
        .await
        .expect("read")
        .expect("the written key reads back");
    assert_eq!(got.key_id, "i1792-key");
}

/// **I1792.** In the single-thread profile a current-thread runtime opens a
/// file-backed SQLite store, migrates it, writes a key and reads it back
/// without starting one thread: the runtime's `on_thread_start` never fires
/// (a blocking-pool thread would fire it) and, where `/proc` answers, the
/// process thread count does not move.
///
/// The control leg runs the same flow in the native profile and must start
/// a blocking-pool thread, so this witness can tell the two apart.
#[cfg(feature = "sqlite")]
#[test]
fn i1792_single_thread_profile_open_write_read_starts_no_thread() {
    // Control: native profile — the blocking pool starts threads.
    {
        let (rt, started) = counting_current_thread();
        rt.block_on(open_write_read());
        assert!(
            started.load(Ordering::SeqCst) > 0,
            "I1792 control: the native profile must start a blocking-pool thread, \
             or this witness cannot see one"
        );
        drop(rt);
    }
    HostSeams::single_thread().install();
    let (rt, started) = counting_current_thread();
    let before = os_threads();
    rt.block_on(open_write_read());
    let after = os_threads();
    rt::uninstall();
    clock::uninstall();
    assert_eq!(
        started.load(Ordering::SeqCst),
        0,
        "I1792: the single-thread profile started a runtime thread"
    );
    if let (Some(b), Some(a)) = (before, after) {
        assert_eq!(a, b, "I1792: the process gained {} thread(s)", a - b);
    }
}

// ── I1793: the dispatch arms ───────────────────────────────────────────────

/// **I1793.** Blocking dispatch runs where the profile says: inline on the
/// calling thread in the single-thread profile, on a blocking-pool thread
/// natively; a panic in the closure is a [`TaskError::Panicked`] from
/// `try_dispatch_blocking` in both arms.
#[test]
fn i1793_dispatch_runs_where_the_profile_says() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let caller = std::thread::current().id();
        let pool = rt::dispatch_blocking(|| std::thread::current().id()).await;
        assert_ne!(pool, caller, "I1793: native dispatch must leave the caller");
        let e = rt::try_dispatch_blocking(|| -> u8 { panic!("i1793 pool") })
            .await
            .expect_err("a panic is an error");
        assert!(
            matches!(e, TaskError::Panicked(ref m) if m.contains("i1793 pool")),
            "{e}"
        );
    });
    rt::install(Arc::new(TokioExecutor::single_thread()));
    rt.block_on(async {
        let caller = std::thread::current().id();
        let inline = rt::dispatch_blocking(|| std::thread::current().id()).await;
        assert_eq!(
            inline, caller,
            "I1793: single-thread dispatch must run inline"
        );
        let tried = rt::try_dispatch_blocking(|| std::thread::current().id())
            .await
            .unwrap();
        assert_eq!(
            tried, caller,
            "I1793: try_dispatch_blocking must run inline"
        );
        let e = rt::try_dispatch_blocking(|| -> u8 { panic!("i1793 inline") })
            .await
            .expect_err("a panic is an error");
        assert!(
            matches!(e, TaskError::Panicked(ref m) if m.contains("i1793 inline")),
            "{e}"
        );
    });
    rt::uninstall();
}

// ── I1797: lifecycle is delivered ──────────────────────────────────────────

/// **I1797.** `Lifecycle::shutdown()` waits for the host: pending until
/// [`LifecycleEvent::Shutdown`] is delivered, resolved after, and sticky
/// (a waiter that arrives later resolves at once). Background / foreground
/// move the state and never resolve it. A persister the host shuts down
/// through the lifecycle drains and exits.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i1797_lifecycle_shutdown_is_the_hosts_event() {
    let lc = Lifecycle::new();
    let waiter = {
        let lc = lc.clone();
        tokio::spawn(async move { lc.shutdown().await })
    };
    lc.deliver(LifecycleEvent::EnterBackground);
    assert!(lc.state().background);
    lc.deliver(LifecycleEvent::EnterForeground);
    tokio::task::yield_now().await;
    assert!(
        crate::host::rt::timeout(Duration::from_millis(100), lc.shutdown())
            .await
            .is_err(),
        "I1797: shutdown resolved before the host delivered it"
    );
    assert!(!waiter.is_finished(), "I1797: a waiter resolved early");
    lc.deliver(LifecycleEvent::Shutdown);
    crate::host::rt::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("I1797: the waiter must resolve on Shutdown")
        .unwrap();
    crate::host::rt::timeout(Duration::from_secs(1), lc.shutdown())
        .await
        .expect("I1797: shutdown is sticky");
    assert_eq!(lc.state().delivered, 3);

    // The persister, shut down by the host's event.
    let backend = Arc::new(crate::store::test_backend::test_backend());
    let dir = tempfile::tempdir().unwrap();
    let journal = Arc::new(crate::journal::Journal::open(dir.path().join("j.redb")).unwrap());
    let signer = test_signer_arc();
    let lc = Lifecycle::new();
    let (ingest, persister) = crate::queue::spawn_persister(
        4,
        backend,
        Arc::new(crate::verify::PythonJsonDumpsCanonicalizer),
        Arc::new(crate::scrub::NullScrubber),
        journal,
        signer.0,
        signer.1,
    );
    let host = {
        let lc = lc.clone();
        tokio::spawn(async move {
            lc.shutdown().await;
            drop(ingest);
            persister.shutdown().await
        })
    };
    lc.deliver(LifecycleEvent::Shutdown);
    crate::host::rt::timeout(Duration::from_secs(10), host)
        .await
        .expect("I1797: the persister must drain once the host delivers Shutdown")
        .unwrap()
        .expect("I1797: the persister exits cleanly");
}

#[cfg(feature = "sqlite")]
fn test_signer_arc() -> (Arc<dyn ciris_keyring::HardwareSigner>, String) {
    use ciris_keyring::Ed25519SoftwareSigner;
    let key_id = "i1797-scrub-key".to_owned();
    let mut signer = Ed25519SoftwareSigner::new(&key_id);
    signer.import_key(&[0x5Au8; 32]).expect("import_key");
    (Arc::new(signer), key_id)
}

// ── I1798: teardown drops inline on one thread ─────────────────────────────

/// **I1798.** In the single-thread profile a retirement drops its payload
/// before `retire_payload` returns, on the calling thread, and leaves
/// nothing in flight. The control leg (native) hands it to the teardown
/// thread.
#[test]
fn i1798_single_thread_teardown_drops_inline() {
    struct Witness(Arc<std::sync::Mutex<Option<std::thread::ThreadId>>>);
    impl Drop for Witness {
        fn drop(&mut self) {
            *self.0.lock().unwrap() = Some(std::thread::current().id());
        }
    }
    let me = std::thread::current().id();

    let seen = Arc::new(std::sync::Mutex::new(None));
    crate::ffi::teardown::retire_payload(Box::new(Witness(seen.clone())));
    assert!(crate::ffi::teardown::wait_quiesced(Duration::from_secs(10)));
    assert_ne!(
        *seen.lock().unwrap(),
        Some(me),
        "I1798 control: native teardown must drop on its own thread"
    );

    rt::install(Arc::new(TokioExecutor::single_thread()));
    let seen = Arc::new(std::sync::Mutex::new(None));
    crate::ffi::teardown::retire_payload(Box::new(Witness(seen.clone())));
    let dropped_on = *seen.lock().unwrap();
    let in_flight = crate::ffi::teardown::in_flight();
    rt::uninstall();
    assert_eq!(
        dropped_on,
        Some(me),
        "I1798: the single-thread profile must drop inline, before returning"
    );
    assert_eq!(in_flight, 0, "I1798: nothing may be left in flight");
}

// ── I1799: the journal replay awaits in place ─────────────────────────────

/// **I1799.** The persister's journal replay runs on a current-thread
/// runtime in the single-thread profile without starting a thread (v61
/// bridged each entry through a scoped OS thread and `block_on`). A journal
/// entry the pipeline refuses halts the replay with the entry kept, as the
/// synchronous `Journal::replay` always did.
#[cfg(feature = "sqlite")]
#[test]
fn i1799_journal_replay_awaits_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let journal = Arc::new(crate::journal::Journal::open(dir.path().join("j.redb")).unwrap());
    journal.append(b"i1799-not-a-batch").unwrap();
    let backend = Arc::new(crate::store::test_backend::test_backend());
    HostSeams::single_thread().install();
    let (rt, started) = counting_current_thread();
    let before = os_threads();
    let j = journal.clone();
    rt.block_on(async move {
        let signer = test_signer_arc();
        let (ingest, persister) = crate::queue::spawn_persister(
            4,
            backend,
            Arc::new(crate::verify::PythonJsonDumpsCanonicalizer),
            Arc::new(crate::scrub::NullScrubber),
            j,
            signer.0,
            signer.1,
        );
        drop(ingest);
        crate::host::rt::timeout(Duration::from_secs(10), persister.shutdown())
            .await
            .expect("I1799: the persister must finish")
            .expect("I1799: clean exit");
    });
    let after = os_threads();
    rt::uninstall();
    clock::uninstall();
    assert_eq!(
        journal.pending_count().unwrap(),
        1,
        "I1799: a refused entry halts the replay and stays journaled"
    );
    assert_eq!(
        started.load(Ordering::SeqCst),
        0,
        "I1799: a runtime thread started"
    );
    if let (Some(b), Some(a)) = (before, after) {
        assert_eq!(a, b, "I1799: the process gained {} thread(s)", a - b);
    }
}
