//! v61.1.0 (CIRISPersist#1231): I1550–I1557. No raw tokio runtime type
//! that persist's `.so` built is walked by a foreign copy of persist's code.
//!
//! **The hazard.** A consumer (Edge) links persist as an rlib, so its `.so`
//! carries its own copy of every monomorphic persist function, compiled
//! against its own tokio. Edge holds a `PostgresBackend` that persist's `.so`
//! built and calls its methods, which runs EDGE's copy of
//! `checkout_bounded` on whatever thread polls it. Up to v61.0.5 the backend
//! kept a raw `tokio::runtime::Handle` (`persist_rt`). On persist's executor
//! worker, where Edge's tokio has no runtime, Edge's copy took the fallback
//! arm and called `rt.spawn(...)`: Edge's tokio 1.53 walked a `Handle` laid
//! out by persist's tokio 1.54. The result was a SIGSEGV in `OwnedTasks`. This
//! is the #354 / CIRISServer#705 class.
//!
//! **The fix.** The backend holds an `Arc<dyn PersistRuntimeTimer>` that
//! persist's `.so` built (`store::postgres_runtime_connect`). A foreign copy
//! reaches persist's runtime only through the vtable pointer persist wrote.
//! Making the fallback `#[inline(never)]` or non-generic would not help,
//! because the foreign crate compiles its own copy of such a function too.
//!
//! **Why a from-disk gate carries the structural half.** The crash needs two
//! tokio copies with different layouts in one process. One crate's test
//! binary links exactly one tokio, so no runtime witness here can reproduce
//! it. The runtime witnesses (I1550–I1554) cover the behaviour of the arm
//! the foreign copy takes: off-runtime polling, the timer, its cancellation,
//! and the starved and free pools. The gates (I1555–I1557) keep a raw
//! `Handle` from coming back onto a path a foreign copy reads as data.

use std::path::PathBuf;

use super::pool_checkout_gate::{blank, fn_body, rust_files};

// ── from disk: no stored runtime type outside the vetted holders ──────────

/// The structs that may hold a tokio `Handle`/`Runtime`, each with the
/// reason no foreign copy of persist's code reads it as data. Adding a holder
/// here is a review event: name how the foreign copy is kept off it.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "src/store/postgres_runtime_connect.rs",
        "PersistRuntimeConnect",
        "deadpool holds it as the `Box<dyn Connect>` persist's .so built; only that vtable's code reads the Handle (#705)",
    ),
    (
        "src/store/postgres_runtime_connect.rs",
        "CapturedRuntime",
        "held only as `Arc<dyn PersistRuntimeTimer>` persist's .so built (#1231)",
    ),
    (
        "src/audit/merkle_store.rs",
        "PgMerkleStore",
        "built per call from the running copy's own `Handle::current()` and dropped in that call",
    ),
    (
        "src/audit/merkle_store.rs",
        "SqliteMerkleStore",
        "built per call from the running copy's own `Handle::current()` and dropped in that call",
    ),
    (
        "src/ffi/pyo3.rs",
        "SharedRuntime",
        "owned by the PyEngine pyclass; reached only by Python calls into persist's own .so",
    ),
];

/// The backends a foreign copy is HANDED and walks as data. Never a holder.
const HANDED_TO_FOREIGN_COPIES: [&str; 2] = ["PostgresBackend", "SqliteBackend"];

fn is_ident(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}

/// Every `struct`/`enum` in `code` (already blanked) whose body names
/// `Handle` or `Runtime` as a whole word (`JoinHandle`, `AbortHandle` and
/// `tokio::runtime` are other words), as `(type, 1-based line, word)`.
fn stored_runtime_types(code: &str) -> Vec<(String, usize, &'static str)> {
    let b = code.as_bytes();
    let mut hits = Vec::new();
    for kw in ["struct", "enum"] {
        let mut from = 0usize;
        while let Some(p) = code[from..].find(kw) {
            let at = from + p;
            from = at + kw.len();
            let before_ok = at == 0 || !is_ident(b[at - 1]);
            let after_ok = b.get(from).is_some_and(|c| c.is_ascii_whitespace());
            if !before_ok || !after_ok {
                continue;
            }
            let mut i = from;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            let name_start = i;
            while i < b.len() && is_ident(b[i]) {
                i += 1;
            }
            if i == name_start {
                continue;
            }
            let name = code[name_start..i].to_owned();
            // The body opens at the first `{` or `(` outside generics; a `;`
            // first is a unit struct.
            let mut angle = 0usize;
            let mut open = None;
            while i < b.len() {
                match b[i] {
                    b'<' => angle += 1,
                    b'>' => angle = angle.saturating_sub(1),
                    b'{' | b'(' if angle == 0 => {
                        open = Some(i);
                        break;
                    }
                    b';' if angle == 0 => break,
                    _ => {}
                }
                i += 1;
            }
            let Some(open) = open else { continue };
            let (o, c) = if b[open] == b'{' {
                (b'{', b'}')
            } else {
                (b'(', b')')
            };
            let mut depth = 0usize;
            let mut close = b.len();
            for (k, &ch) in b.iter().enumerate().skip(open) {
                if ch == o {
                    depth += 1;
                } else if ch == c {
                    depth -= 1;
                    if depth == 0 {
                        close = k;
                        break;
                    }
                }
            }
            for word in ["Handle", "Runtime"] {
                let body = &code[open..close];
                let mut f = 0usize;
                while let Some(q) = body[f..].find(word) {
                    let w = open + f + q;
                    f += q + word.len();
                    let pre = w.checked_sub(1).map(|k| b[k]);
                    let post = b.get(w + word.len()).copied();
                    if pre.is_some_and(is_ident) || post.is_some_and(is_ident) {
                        continue;
                    }
                    let line = code[..w].matches('\n').count() + 1;
                    hits.push((name.clone(), line, word));
                }
            }
        }
    }
    hits.sort();
    hits
}

/// The `Handle` words in `region` (already blanked) that are not the
/// running copy asking its own tokio, `Handle::try_current()`.
fn raw_handles(region: &str) -> usize {
    let asked = region.replace("Handle::try_current()", "");
    let b = asked.as_bytes();
    let mut n = 0usize;
    let mut f = 0usize;
    while let Some(q) = asked[f..].find("Handle") {
        let w = f + q;
        f = w + "Handle".len();
        let pre = w.checked_sub(1).map(|k| b[k]);
        let post = b.get(f).copied();
        if !pre.is_some_and(is_ident) && !post.is_some_and(is_ident) {
            n += 1;
        }
    }
    n
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// **I1555.** No struct or enum anywhere in `src/` (tests included) holds a
/// tokio `Handle` or `Runtime` unless [`ALLOWED`] names it with its reason.
/// Neither backend a foreign copy is handed ever holds one, on postgres or
/// sqlite.
#[test]
fn i1555_no_backend_a_foreign_copy_walks_holds_a_raw_runtime() {
    let root = root();
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();
    assert!(
        files.len() > 200,
        "I1555: the scan reached {} files under src/; it would pass vacuously",
        files.len()
    );
    let mut offenders = Vec::new();
    let mut found = std::collections::BTreeSet::new();
    let mut seen_backends = std::collections::BTreeSet::new();
    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .expect("under root")
            .to_string_lossy()
            .replace('\\', "/");
        let code = blank(&super::tree_read::read(path));
        for backend in HANDED_TO_FOREIGN_COPIES {
            if code.contains(&format!("pub struct {backend} {{")) {
                seen_backends.insert(backend);
            }
        }
        for (ty, line, word) in stored_runtime_types(&code) {
            if HANDED_TO_FOREIGN_COPIES.contains(&ty.as_str()) {
                offenders.push(format!(
                    "  {rel}:{line}: `{ty}` holds a raw `{word}`; a foreign copy of persist \
                     walks this backend as data (#1231). Hold an `Arc<dyn …>` persist's .so \
                     builds instead (`postgres_runtime_connect::PersistTimer`)"
                ));
            } else if ALLOWED.iter().any(|(f, t, _)| *f == rel && *t == ty) {
                found.insert((rel.clone(), ty));
            } else {
                offenders.push(format!(
                    "  {rel}:{line}: `{ty}` holds a raw tokio `{word}`, and `ALLOWED` does not \
                     name it with the reason no foreign copy reads it"
                ));
            }
        }
    }
    super::tree_read::assert_unmoved();
    assert_eq!(
        seen_backends.len(),
        HANDED_TO_FOREIGN_COPIES.len(),
        "I1555: the scan did not find every backend struct ({seen_backends:?}); its anchor moved"
    );
    for (f, t, _) in ALLOWED {
        assert!(
            found.contains(&((*f).to_owned(), (*t).to_owned())),
            "I1555: `ALLOWED` names `{t}` in {f}, which no longer holds a runtime type: \
             remove the entry"
        );
    }
    assert!(
        offenders.is_empty(),
        "CIRISPersist#1231: a raw tokio runtime type a foreign copy can reach:\n{}",
        offenders.join("\n")
    );
}

/// **I1556.** The functions a foreign copy runs on the checkout path,
/// `checkout_bounded` and the retry `pause`, name a `Handle` only to ask
/// the running copy's own tokio (`Handle::try_current()`). Their signatures
/// and bodies carry no `Handle` of persist's.
#[test]
fn i1556_the_checkout_path_takes_no_raw_handle() {
    let root = root();
    for (file, sig) in [
        ("src/store/postgres.rs", "fn checkout_bounded("),
        ("src/store/postgres_runtime_connect.rs", "fn pause("),
    ] {
        let code = blank(&super::tree_read::read(&root.join(file)));
        let at = code
            .find(sig)
            .unwrap_or_else(|| panic!("I1556: {file} has no `{sig}`; the anchor moved"));
        let (_, end) = fn_body(&code, sig).unwrap_or_else(|| panic!("I1556: `{sig}` has no body"));
        let region = &code[at..end];
        assert!(
            region.contains("Handle::try_current()"),
            "I1556: `{sig}` no longer asks the running copy's tokio; the anchor moved"
        );
        assert_eq!(
            raw_handles(region),
            0,
            "CIRISPersist#1231: `{sig}` in {file} takes or builds a raw tokio `Handle`. A \
             foreign copy of it would walk persist's runtime with its own tokio. Go \
             through `postgres_runtime_connect::PersistRuntimeTimer`"
        );
    }
    super::tree_read::assert_unmoved();
}

/// **I1557.** The scanners read fields and calls, not mentions: a planted
/// raw `Handle` field is found on its line, and `JoinHandle`, a comment, a
/// string and `Handle::try_current()` are not.
#[test]
fn i1557_the_gates_read_types_not_mentions() {
    let planted = "pub struct PostgresBackend {\n    pool: Pool,\n    rt: Option<tokio::runtime::Handle>,\n}\n";
    assert_eq!(
        stored_runtime_types(&blank(planted)),
        vec![("PostgresBackend".to_owned(), 3, "Handle")]
    );
    let tuple = "struct Holder(Arc<Runtime>);";
    assert_eq!(
        stored_runtime_types(&blank(tuple)),
        vec![("Holder".to_owned(), 1, "Runtime")]
    );
    let generic = "struct G<T: Into<u8>> {\n    h: Handle,\n}\n";
    assert_eq!(
        stored_runtime_types(&blank(generic)),
        vec![("G".to_owned(), 2, "Handle")]
    );
    let not_runtime = "struct A {\n    j: JoinHandle<()>,\n    // rt: Handle\n    s: &'static str,\n}\nconst S: &str = \"struct B { h: Handle }\";\nstruct U;\n";
    assert!(stored_runtime_types(&blank(not_runtime)).is_empty());
    let asks = "fn checkout_bounded(p: &Pool) { match tokio::runtime::Handle::try_current() {} }";
    assert_eq!(raw_handles(&blank(asks)), 0);
    let takes =
        "fn checkout_bounded(rt: Option<&tokio::runtime::Handle>) { Handle::try_current() }";
    assert_eq!(raw_handles(&blank(takes)), 1);
    let builds = "fn pause() { let h = tokio::runtime::Handle::current(); }";
    assert_eq!(raw_handles(&blank(builds)), 1);
}

// ── runtime: the arm a foreign copy takes ────────────────────────────────

#[cfg(feature = "postgres")]
mod runtime {
    use std::future::Future;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake};
    use std::time::{Duration, Instant};

    use crate::store::postgres_runtime_connect::{
        capture_persist_timer, pause, PersistTimer, TIMER_STARTS,
    };

    /// Poll `f` to completion on THIS thread with no tokio runtime at all.
    /// To persist's tokio, a foreign tokio copy's thread looks like this.
    fn block_on_no_runtime<F: Future>(f: F) -> F::Output {
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

    fn persist_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("persist runtime")
    }

    fn captured(rt: &tokio::runtime::Runtime) -> PersistTimer {
        rt.block_on(async { capture_persist_timer() })
            .expect("a timer is captured on persist's runtime")
    }

    /// Wait (bounded) for persist's runtime to hold `want` live tasks.
    fn settle_to(rt: &tokio::runtime::Runtime, want: usize, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while rt.metrics().num_alive_tasks() != want {
            assert!(
                Instant::now() < deadline,
                "{what}: persist's runtime still holds {} live tasks, want {want}",
                rt.metrics().num_alive_tasks()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// **I1550.** A timer captured on persist's runtime and polled from a
    /// thread with no runtime waits its full duration. The task runs on
    /// persist's runtime, started by persist's code through the vtable.
    /// Off-runtime capture is `None`.
    #[test]
    fn i1550_the_persist_timer_waits_on_a_thread_without_a_runtime() {
        assert!(
            capture_persist_timer().is_none(),
            "I1550: no runtime on the constructing thread means no timer"
        );
        let rt = persist_runtime();
        let timer = captured(&rt);
        let before = TIMER_STARTS.load(Ordering::Relaxed);
        let wait = Duration::from_millis(80);
        let started = Instant::now();
        block_on_no_runtime(timer.sleep(wait));
        assert!(
            started.elapsed() >= wait,
            "I1550: the timer fired after {:?}, before its {wait:?}",
            started.elapsed()
        );
        assert!(
            TIMER_STARTS.load(Ordering::Relaxed) > before,
            "I1550: the wait was started by persist's timer"
        );
        rt.shutdown_background();
    }

    /// **I1551.** Dropping the timer's future, which the checkout does when
    /// it wins the race, aborts the timer task on persist's runtime. Without
    /// the abort a sleeping task stays there for the rest of the wait (30 s
    /// in production).
    #[test]
    fn i1551_dropping_the_timer_aborts_its_task() {
        let rt = persist_runtime();
        let timer = captured(&rt);
        let base = rt.metrics().num_alive_tasks();
        let fired = timer.sleep(Duration::from_secs(3600));
        assert_eq!(
            rt.metrics().num_alive_tasks(),
            base + 1,
            "I1551: the timer runs as a task on persist's runtime"
        );
        drop(fired);
        settle_to(&rt, base, "I1551: a dropped timer is aborted");
        rt.shutdown_background();
    }

    /// **I1552.** The retry pause never asks a runtime-less thread for a
    /// reactor. It waits on persist's timer when there is one and returns
    /// at once when there is none. `tokio::time::sleep` panicked there.
    #[test]
    fn i1552_the_retry_pause_off_runtime_uses_persist_timer() {
        let rt = persist_runtime();
        let timer = captured(&rt);
        let before = TIMER_STARTS.load(Ordering::Relaxed);
        let wait = Duration::from_millis(80);
        let started = Instant::now();
        let t = timer.clone();
        let joined = std::thread::spawn(move || block_on_no_runtime(pause(wait, Some(&*t)))).join();
        assert!(
            joined.is_ok(),
            "I1552: an off-runtime pause panicked instead of waiting on persist's timer"
        );
        assert!(started.elapsed() >= wait, "I1552: {:?}", started.elapsed());
        assert!(TIMER_STARTS.load(Ordering::Relaxed) > before, "I1552");
        let started = Instant::now();
        let joined = std::thread::spawn(move || {
            block_on_no_runtime(pause(Duration::from_secs(3600), None));
        })
        .join();
        assert!(joined.is_ok(), "I1552: no timer, no panic");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "I1552: with no timer anywhere the pause returns at once"
        );
        drop(timer);
        rt.shutdown_background();
    }

    /// **I1553 (postgres).** A backend built on persist's runtime and
    /// polled on a starved pool from a thread with no runtime answers a
    /// typed `PoolExhausted` within its wait. The wait is timed by persist's
    /// timer, not by a raw `Handle` the polling copy spawns on.
    #[test]
    fn i1553_a_starved_pool_off_runtime_is_timed_by_persist_timer() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let rt = persist_runtime();
        let wait = Duration::from_secs(2);
        let backend = Arc::new(
            rt.block_on(
                crate::store::postgres::PostgresBackend::connect_with_pool_for_test(&dsn, 1, wait),
            )
            .expect("connect"),
        );
        let held = rt
            .block_on(backend.get_client())
            .expect("the only connection");
        let before = TIMER_STARTS.load(Ordering::Relaxed);
        let b = backend.clone();
        let started = Instant::now();
        let joined = std::thread::spawn(move || {
            block_on_no_runtime(async move { b.get_client().await.map(|_| ()) })
        })
        .join();
        match joined {
            Ok(Err(crate::store::Error::PoolExhausted { waited })) => assert_eq!(waited, wait),
            other => panic!(
                "I1553: a typed exhaustion, not {:?}",
                other.map(|r| r.err())
            ),
        }
        assert!(
            started.elapsed() < wait * 3,
            "I1553: {:?}",
            started.elapsed()
        );
        assert!(
            TIMER_STARTS.load(Ordering::Relaxed) > before,
            "I1553: the off-runtime wait ran on persist's timer"
        );
        drop(held);
        drop(backend);
        rt.shutdown_background();
    }

    /// **I1554 (postgres).** A free pool polled from a thread with no
    /// runtime hands back its connection, and the timer it raced is aborted
    /// on persist's runtime rather than left sleeping out the 30 s wait.
    #[test]
    fn i1554_a_free_pool_off_runtime_returns_and_cancels_its_timer() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let rt = persist_runtime();
        let backend = Arc::new(
            rt.block_on(
                crate::store::postgres::PostgresBackend::connect_with_pool_for_test(
                    &dsn,
                    1,
                    Duration::from_secs(30),
                ),
            )
            .expect("connect"),
        );
        // Warm the one connection on persist's runtime so the off-runtime
        // checkout reuses it (its driver task is part of the baseline).
        drop(rt.block_on(backend.get_client()).expect("warm"));
        let base = rt.metrics().num_alive_tasks();
        let before = TIMER_STARTS.load(Ordering::Relaxed);
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
            "I1554: an off-runtime checkout on a free pool returns a working connection"
        );
        assert!(
            TIMER_STARTS.load(Ordering::Relaxed) > before,
            "I1554: the checkout raced persist's timer"
        );
        settle_to(&rt, base, "I1554: the losing timer is aborted");
        drop(backend);
        rt.shutdown_background();
    }
}
