//! v62.0.0 (slice A, P9) — the native host's teardown adapter, moved here
//! from `engine::teardown`. A single-thread host (FSD WASM_NODE §5.2,
//! `ciris-persist-teardown` → inline drop) never reaches this thread: under
//! [`crate::host::rt::blocking_runs_inline`] every retirement drops inline.
//!
//! v24.3.0 (CIRISPersist#572) — bounded, caller-thread-free teardown
//! of a tokio runtime and everything it was driving.
//!
//! # The defect this exists to close
//!
//! `tokio::runtime::Runtime`'s `Drop` **blocks the dropping thread**
//! until every worker has parked and every `spawn_blocking` task that
//! has already begun executing has run to completion. There is no
//! timeout on that wait and no way to cancel a blocking task — the
//! SQLite backend runs every statement through `spawn_blocking`, so
//! "already begun" is the normal state during a busy teardown.
//!
//! That is merely slow in a Rust program. Under PyO3 it is fatal: the
//! last `Arc<Runtime>` reference is normally released from inside
//! CPython's `Py_DECREF` — a `gc.collect()`, an interpreter shutdown,
//! a capsule destructor — and **CPython holds the GIL for the whole
//! of a deallocation**. A blocking wait there does not stall one
//! thread, it stalls the interpreter: no other Python thread can be
//! scheduled, so watchdogs (pytest-timeout's thread-method timer,
//! `faulthandler`, signal handlers written in Python) never fire. The
//! process presents as a silent native wedge with no Rust-side error
//! at all, which is exactly the residual flake reported downstream as
//! CIRISAgent#956 and filed here as CIRISPersist#572.
//!
//! # The rule
//!
//! **Nothing that can block may be dropped on a thread that might
//! hold the GIL.** Instead the payload is moved to a dedicated OS
//! thread — which by construction holds no GIL — and dropped there.
//! The caller's cost is one `thread::spawn`; the wait still happens,
//! it just happens somewhere it cannot take the interpreter with it.
//!
//! # Why this is not "leaking the runtime to dodge the wait"
//!
//! It is a deferred join, not a leak: the runtime is really dropped,
//! really winds its workers down, and really waits for its in-flight
//! blocking tasks — and [`wait_quiesced`] lets a caller (a test
//! fixture, a shutdown sequence) block on that completion with a
//! bound, off the GIL. The only true leak is the thread-spawn-failed
//! fallback in [`retire_runtime`], which is documented there.
//!
//! # Ordering
//!
//! Teardown payloads are dropped in tuple/field declaration order, and
//! callers are expected to put the runtime FIRST: a backend handle
//! freed before the runtime has finished winding down is a
//! use-after-free for any blocking task still touching it (the
//! historical "Bus error" half of #572's symptom set).

use std::any::Any;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use tokio::runtime::Runtime;

thread_local! {
    /// Set only on the threads [`spawn_drop`] creates. It marks
    /// "blocking is allowed here" — those threads are the one
    /// place in the process that provably cannot be holding the
    /// GIL, so a nested [`retire_runtime`] on such a thread drops
    /// inline rather than spawning another thread (which would
    /// break the runtime-before-backend ordering).
    static ON_TEARDOWN_THREAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `(count of retirements not yet finished, condvar)`.
static IN_FLIGHT: OnceLock<(Mutex<usize>, Condvar)> = OnceLock::new();

fn gauge() -> &'static (Mutex<usize>, Condvar) {
    IN_FLIGHT.get_or_init(|| (Mutex::new(0), Condvar::new()))
}

/// True when the calling thread is a teardown thread — i.e. when
/// blocking here is safe.
pub fn on_teardown_thread() -> bool {
    ON_TEARDOWN_THREAD.with(|c| c.get())
}

/// Number of retirements handed off and not yet finished.
pub fn in_flight() -> usize {
    *gauge().0.lock().unwrap_or_else(|e| e.into_inner())
}

fn finish_one() {
    let (lock, cv) = gauge();
    let mut n = lock.lock().unwrap_or_else(|e| e.into_inner());
    *n = n.saturating_sub(1);
    cv.notify_all();
}

/// Move `payload` onto a dedicated OS thread and drop it there.
///
/// Returns `Err(payload)` — handing ownership back, undamaged —
/// when the thread could not be spawned, so the caller can pick
/// a fallback that suits the payload. Never blocks.
fn spawn_drop<T: Send + 'static>(payload: T) -> Result<(), T> {
    {
        let (lock, _) = gauge();
        *lock.lock().unwrap_or_else(|e| e.into_inner()) += 1;
    }
    // The payload rides in a shared slot rather than being moved
    // straight into the closure, because `thread::Builder::spawn`
    // consumes (and on failure destroys) its closure — and
    // destroying the closure would perform the very blocking drop
    // we are trying to move off this thread.
    let cargo = Arc::new(Mutex::new(Some(payload)));
    let theirs = Arc::clone(&cargo);
    let spawned = std::thread::Builder::new()
        .name("ciris-persist-teardown".to_string())
        .spawn(move || {
            ON_TEARDOWN_THREAD.with(|c| c.set(true));
            drop(theirs.lock().unwrap_or_else(|e| e.into_inner()).take());
            finish_one();
        });
    match spawned {
        // Deliberately detached: joining it is what
        // `wait_quiesced` is for, with a bound.
        Ok(_join) => Ok(()),
        Err(e) => {
            finish_one();
            let payload = cargo
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take()
                .expect("payload is only taken by the spawned thread");
            tracing::error!(
                error = %e,
                "ciris-persist v24.3.0 (#572): could not spawn a teardown thread"
            );
            Err(payload)
        }
    }
}

/// Retire a tokio runtime plus everything that must outlive its
/// shutdown, without blocking the calling thread.
///
/// `keepalive` is dropped **after** the runtime has fully wound
/// down. Pass the backend / pool handles the runtime's in-flight
/// blocking tasks are still touching; freeing those first is the
/// SIGBUS half of #572.
///
/// Safe to call while holding the GIL. Safe to call from a
/// `Drop` impl.
pub fn retire_runtime(rt: Runtime, keepalive: Box<dyn Any + Send>) {
    // v62.0.0 (P9) — a single-thread host has no second thread to hand this
    // to and no GIL to protect: inline drop (FSD WASM_NODE §5.2).
    if on_teardown_thread() || crate::host::rt::blocking_runs_inline() {
        // Already off the GIL and already inside an ordered
        // teardown — do the wait here so the caller's remaining
        // fields (the backend, above all) drop strictly after it.
        drop(rt);
        drop(keepalive);
        return;
    }
    // Tuple fields drop in declaration order: runtime, then the
    // things it was driving. That ordering is the whole point.
    if let Err((rt, keepalive)) = spawn_drop((rt, keepalive)) {
        // No thread to hand this to, and we may be holding the
        // GIL — blocking is the one thing we must not do. Signal
        // shutdown without waiting and forget the keepalive:
        // leaking a pool is survivable, wedging the interpreter
        // is not. Thread exhaustion is already a hard failure of
        // the process, so this is loud rather than silent.
        tracing::error!(
            "ciris-persist v24.3.0 (#572): backgrounding runtime shutdown \
             and leaking its keepalive — teardown thread unavailable"
        );
        rt.shutdown_background();
        std::mem::forget(keepalive);
    }
}

/// Retire an arbitrary payload whose `Drop` may block (an engine
/// cell, a connection pool) on a teardown thread.
///
/// Same contract as [`retire_runtime`]: never blocks the caller,
/// safe under the GIL. On thread-spawn failure the payload is
/// forgotten rather than dropped, for the same reason.
pub fn retire_payload(payload: Box<dyn Any + Send>) {
    if on_teardown_thread() || crate::host::rt::blocking_runs_inline() {
        drop(payload);
        return;
    }
    if let Err(payload) = spawn_drop(payload) {
        tracing::error!(
            "ciris-persist v24.3.0 (#572): leaking a teardown payload — \
             teardown thread unavailable"
        );
        std::mem::forget(payload);
    }
}

/// Block — with a bound — until every retirement handed off so far
/// has finished. Returns `true` if the process quiesced, `false`
/// on timeout.
///
/// # This must never be called while holding the GIL
///
/// It is the one blocking call in this module, and it exists so a
/// caller can *choose* to wait somewhere safe. The PyO3 surface
/// only ever reaches it from inside `py.detach(...)`. Calling it
/// with the GIL held reintroduces exactly the wedge the module
/// exists to prevent.
///
/// A `false` return is a typed, loggable outcome, not an error:
/// the retirement keeps running on its own thread and the caller
/// gets its thread back.
pub fn wait_quiesced(timeout: Duration) -> bool {
    debug_assert!(
        !on_teardown_thread(),
        "wait_quiesced from a teardown thread would deadlock on itself"
    );
    let (lock, cv) = gauge();
    let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    let (_guard, res) = cv
        .wait_timeout_while(guard, timeout, |n| *n > 0)
        .unwrap_or_else(|e| e.into_inner());
    !res.timed_out()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A keepalive that records, at the moment it is dropped,
    /// whether the runtime had already finished winding down.
    struct OrderWitness {
        task_finished: Arc<AtomicBool>,
        saw_finished: Arc<AtomicBool>,
    }

    impl Drop for OrderWitness {
        fn drop(&mut self) {
            self.saw_finished
                .store(self.task_finished.load(Ordering::SeqCst), Ordering::SeqCst);
        }
    }

    /// v31.0.0 (CIRISPersist#658) — how long a test's in-flight blocking
    /// task stays in flight when nothing releases it.
    ///
    /// It is NOT a budget and no assertion compares against it as one. Both
    /// tests below hold a `spawn_blocking` task open on a channel and
    /// release it explicitly, so in a healthy run the task waits
    /// microseconds and this value is never reached. It exists so that a
    /// REGRESSION — a `retire_runtime` that blocks its caller, which would
    /// otherwise deadlock against the very channel meant to hold the task
    /// open — self-releases and lands on a named assertion with a
    /// diagnosis, instead of hanging until nextest SIGKILLs it at
    /// `terminate-after` (six minutes, no message, no attribution).
    ///
    /// Comfortably under that six-minute kill, and three orders of
    /// magnitude above anything the healthy path does.
    const HELD_OPEN: Duration = Duration::from_secs(30);

    /// v24.3.0 (CIRISPersist#572) — the ordering contract, with no
    /// backend and no Python in the picture: `retire_runtime`
    /// releases the keepalive strictly AFTER the runtime's
    /// in-flight blocking work is done.
    ///
    /// This is what makes the keepalive worth passing. Freeing a
    /// backend handle while a `spawn_blocking` task is still using
    /// it is a use-after-free, and it is the half of #572 that
    /// presented downstream as "Bus error" rather than as a hang.
    ///
    /// # Why there is no elapsed-time assertion here
    ///
    /// v31.0.0 (CIRISPersist#658) — "the caller is not the one paying for
    /// the wait" used to be spelled `t0.elapsed() < 150ms` around a call
    /// whose one job is to SPAWN AN OS THREAD. That measures the
    /// scheduler: on a contended box a `thread::Builder::spawn` plus a
    /// mutex acquisition can take longer than 150 ms while the code under
    /// test is perfectly correct, and the failure it produces names a
    /// duration rather than a defect.
    ///
    /// The property was never a duration. It is an ORDERING: `retire_runtime`
    /// returns to its caller while the runtime's blocking work is still
    /// UNFINISHED. So the task is held open on a channel that only this
    /// test can close, and the assertion reads the work's own completion
    /// flag. On a correct implementation the task cannot possibly have
    /// finished, at any machine speed, because nothing has released it —
    /// the assertion is exact rather than generous.
    #[test]
    #[serial_test::serial(runtime_teardown_gauge)]
    fn keepalive_outlives_the_runtimes_in_flight_work() {
        let task_finished = Arc::new(AtomicBool::new(false));
        let saw_finished = Arc::new(AtomicBool::new(false));

        let rt = Runtime::new().expect("tokio runtime");
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        // The blocking task is held in flight by a CHANNEL, not by a sleep:
        // the test decides when it finishes, so "still in flight" is a fact
        // rather than a race against a timer.
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let flag = Arc::clone(&task_finished);
        rt.spawn_blocking(move || {
            let _ = started_tx.send(());
            // `recv_timeout`, not `recv`: see `HELD_OPEN`. A blocking
            // `recv` would turn the regression this test exists to catch
            // into an unattributable SIGKILL.
            let _ = release_rx.recv_timeout(HELD_OPEN);
            flag.store(true, Ordering::SeqCst);
        });
        // Deterministic: the task has begun, so tokio's shutdown
        // is obliged to wait for it.
        started_rx.recv().expect("blocking task must start");

        let witness = OrderWitness {
            task_finished: Arc::clone(&task_finished),
            saw_finished: Arc::clone(&saw_finished),
        };
        retire_runtime(rt, Box::new(witness));
        // The caller is not the one paying for the wait — and nothing has
        // released the task yet, so on a correct implementation this flag
        // is false no matter how slow the box is.
        assert!(
            !task_finished.load(Ordering::SeqCst),
            "retire_runtime did not return until the runtime's in-flight blocking task \
             had finished. Nothing in this test released that task, so the only way to \
             observe it finished is to have waited {HELD_OPEN:?} for its own self-release \
             — i.e. retire_runtime blocked its caller on work the caller does not own \
             (#572). This is not a slow machine; it is the contract inverted."
        );

        // Now let the runtime wind down, and only now.
        release_tx
            .send(())
            .expect("the blocking task must still be waiting to be released");
        assert!(
            wait_quiesced(Duration::from_secs(10)),
            "retirement never completed"
        );
        assert!(
            saw_finished.load(Ordering::SeqCst),
            "the keepalive was dropped before the runtime finished \
             its in-flight blocking task (#572 use-after-free)"
        );
        assert_eq!(in_flight(), 0);
    }

    /// v24.3.0 (CIRISPersist#572) — a `false` from `wait_quiesced`
    /// is a value, not a hang: the bound is honoured and the
    /// retirement keeps running on its own thread.
    ///
    /// # The one place a real-time bound IS the property
    ///
    /// v31.0.0 (CIRISPersist#658) — unlike its neighbour, this test cannot
    /// be rewritten free of wall clocks: `wait_quiesced(d)` takes a
    /// `Duration` and the whole claim is that it honours it. What it CAN
    /// do is stop measuring the machine.
    ///
    /// The in-flight work is held open for [`HELD_OPEN`] instead of a
    /// 800 ms sleep, which widens the gap the assertion has to straddle
    /// from 100 ms-vs-800 ms (8x) to 100 ms-vs-30 s (300x). The two
    /// readings a breach must tell apart are "waited for the BOUND" and
    /// "waited for the WORK", and the threshold sits a factor of 30 above
    /// the first and a factor of 10 below the second. A scheduler does not
    /// dilate a single condvar timeout by 30x; a `wait_quiesced` that
    /// ignores its argument misses by 300x.
    ///
    /// The LOWER bound is the half that can never flake — slowness only
    /// makes it more true — and it is what stops a `wait_quiesced` that
    /// returns `false` instantly from passing this test vacuously.
    #[test]
    #[serial_test::serial(runtime_teardown_gauge)]
    fn wait_quiesced_honours_its_bound() {
        /// The argument under test.
        const BOUND: Duration = Duration::from_millis(100);
        /// 30x the bound, a tenth of the work. See the doc-comment.
        const CEILING: Duration = Duration::from_secs(3);

        let rt = Runtime::new().expect("tokio runtime");
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        rt.spawn_blocking(move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv_timeout(HELD_OPEN);
        });
        started_rx.recv().expect("blocking task must start");
        retire_runtime(rt, Box::new(()));

        let t0 = std::time::Instant::now();
        let quiesced = wait_quiesced(BOUND);
        let waited = t0.elapsed();
        // Exact, not timing-dependent: nothing has released the in-flight
        // task, so the retirement CANNOT have completed.
        assert!(
            !quiesced,
            "wait_quiesced reported the process quiesced, but the retirement's blocking \
             task has not been released and so cannot have finished — a `true` here is a \
             false quiesce, which is the use-after-free window #572 closed"
        );
        assert!(
            waited >= BOUND,
            "wait_quiesced({BOUND:?}) returned after only {waited:?} — it reported a \
             timeout without waiting for one, so the bound is not a bound"
        );
        assert!(
            waited < CEILING,
            "wait_quiesced({BOUND:?}) took {waited:?}. The in-flight work is held for \
             {HELD_OPEN:?} and the bound is {BOUND:?}, so this is not a slow box: it \
             waited for the WORK instead of for the BOUND, which is the blocking-teardown \
             wedge #572 exists to prevent."
        );

        release_tx
            .send(())
            .expect("the blocking task must still be waiting to be released");
        // Still true afterwards: it finishes on its own.
        assert!(wait_quiesced(Duration::from_secs(10)));
    }
}
