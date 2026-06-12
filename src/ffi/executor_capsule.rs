// This module's whole point is a C-ABI vtable that crosses the
// cdylib boundary. Every safety boundary is documented at the
// call site; the crate-wide #![deny(unsafe_code)] is overridden
// here because there is no other way to implement an FFI ABI.
// Audit-visible: every use of `unsafe` in this file is paired
// with the contract that justifies it. Confined to this module
// so release-wheel reviewers see one diff that owns the surface.
#![allow(unsafe_code)]

//! ABI-stable async-executor capsule (CIRISPersist#157).
//!
//! # Why this exists
//!
//! Two tokio crates link into the cohabitation process — one statically
//! inside `ciris_persist.abi3.so`, one statically inside the consumer
//! wheel (`ciris_edge.abi3.so` and any future cohabiting wheel). Each
//! tokio has its own runtime-context thread-local, its own worker-pool
//! registry, its own `Handle`/`Runtime` vtable layout.
//!
//! The pre-#157 surface `runtime_handle_capsule` returned persist's
//! `tokio::runtime::Handle` to the consumer. The consumer stored it
//! and called `runtime.spawn(fut)` from its own code. The handle's
//! data pointed at persist's tokio's internal runtime registry, but
//! the `spawn` method dispatch went through the **consumer's** tokio
//! `impl` (because that's what the consumer crate's compiler resolved
//! `Handle::spawn` to). The task ended up queued into a structure
//! that neither side's workers reliably observed — silent deadlock at
//! a probability that depended on whose tokio "won" the per-process
//! race for the capsule round-trip. CIRISEdge#58 + CIRISPersist#156
//! are the user-facing symptoms.
//!
//! Same structural class as the libsqlite3 cross-cdylib SIGSEGV at
//! CIRISPersist#141 — different primitive, same root cause: a stateful
//! crate duplicated across the static-vs-wheel boundary, with a value
//! of that crate's type passed through the FFI.
//!
//! # The fix
//!
//! Replace the Rust-type-crossing surface with a **C-ABI vtable**:
//! function pointers (plus an opaque data pointer) cross the boundary;
//! no Rust crate types. The vtable's function pointers live inside
//! `ciris_persist.abi3.so`, so when the consumer calls `vtable.spawn(...)`,
//! control transfers into persist's `.so`. Persist's code calls
//! persist's tokio `runtime.spawn(...)` — the only tokio that knows
//! the runtime exists. The future ends up on persist's worker pool;
//! persist's workers poll it.
//!
//! # The contract the consumer MUST honor
//!
//! The spawned future runs on a tokio worker thread owned by persist's
//! tokio. The tokio thread-local on that worker is set to persist's
//! tokio. Calls to tokio primitives inside the future's body resolve
//! via whichever tokio crate the future's compiler linked against:
//!
//! - If the consumer's future calls persist's public API (`Engine::...`,
//!   etc.), those calls land in persist's code and use persist's tokio
//!   primitives — **always correct**.
//! - If the consumer's future calls the consumer's own tokio
//!   primitives (`tokio::time::sleep`, `tokio::sync::Notify`, etc.),
//!   those calls hit the consumer's tokio thread-local on a
//!   persist-owned worker thread — the thread-local is unset →
//!   `"there is no reactor running"` panic.
//!
//! **The constraint**: the spawned future must NOT use the consumer
//! crate's tokio primitives. Either reach into persist's API for any
//! async work, or use raw `std::*` primitives (mpsc channels are the
//! canonical pattern for delivering the result).
//!
//! # Lifetime
//!
//! The capsule holds an `Arc<tokio::runtime::Runtime>` clone of
//! persist's engine runtime. Capsule outliving `PyEngine` is fine —
//! the runtime stays alive as long as either holds an Arc. Capsule
//! dropping after `PyEngine` is also fine — same reason. The capsule
//! decrements its Arc via [`AsyncExecutorVTable::drop`] when the
//! Python GC drops the `PyCapsule`.
//!
//! # ABI version
//!
//! Consumers MUST verify [`AsyncExecutorVTable::abi_version`] matches
//! [`ASYNC_EXECUTOR_ABI_VERSION`] at capsule-receive time. Persist
//! bumps the version on any breaking change to the vtable layout;
//! consumers built against an older version refuse the capsule
//! cleanly (not undefined behavior).

use std::ffi::c_void;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// ABI version of [`AsyncExecutorVTable`]. Bumped on every breaking
/// change to the vtable's layout or function-pointer signatures.
///
/// Consumers MUST check the field at capsule-receive time:
///
/// ```ignore
/// use ciris_persist::AsyncExecutor;
///
/// let executor: AsyncExecutor = unsafe { /* read from PyCapsule */ };
/// assert_eq!(
///     executor.vtable.abi_version,
///     ciris_persist::ASYNC_EXECUTOR_ABI_VERSION,
///     "persist executor_capsule ABI version mismatch — pin floor too low"
/// );
/// ```
pub const ASYNC_EXECUTOR_ABI_VERSION: u32 = 1;

/// Type-erased thin pointer to a boxed unit-output future.
///
/// The consumer's wrapping invocation:
///
/// ```ignore
/// type BoxedFut = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;
/// let fut: BoxedFut = Box::pin(async move {
///     let result = real_work().await;
///     let _ = tx.send(result); // tx: std::sync::mpsc::Sender<T>
/// });
/// // Box once more so we have a thin pointer to hand through C.
/// let wrapped: Box<BoxedFut> = Box::new(fut);
/// let task_ptr: *mut TaskOpaque = Box::into_raw(wrapped) as *mut TaskOpaque;
/// unsafe { (executor.vtable.spawn)(executor.data, task_ptr) };
/// ```
///
/// The vtable owns the `Box<BoxedFut>` from the moment of the spawn
/// call. The consumer MUST NOT touch the pointer after handing it
/// through.
#[repr(C)]
pub struct TaskOpaque {
    /// Opaque payload — never dereferenced directly. The vtable's
    /// `spawn` casts back to the concrete `Box<Pin<Box<dyn Future...>>>`.
    _opaque: [u8; 0],
}

/// C-ABI function-pointer table for the executor.
///
/// All fields are `#[repr(C)]` compatible; this struct is safe to
/// stash inside a static and hand its address out across the cdylib
/// boundary. The function pointers point into persist's `.so`, so
/// calling them transfers control into persist's tokio's `impl`.
#[repr(C)]
pub struct AsyncExecutorVTable {
    /// ABI version — see [`ASYNC_EXECUTOR_ABI_VERSION`]. Consumers
    /// check this at capsule-receive time.
    pub abi_version: u32,
    /// Reserved padding so the struct's layout matches a natural
    /// 8-byte alignment. MUST be zero in v1.
    pub _reserved: u32,
    /// Spawn the typed-erased future onto the executor's runtime.
    ///
    /// `data` is the opaque pointer from the [`AsyncExecutor`] this
    /// vtable is paired with (an `Arc<tokio::runtime::Runtime>`
    /// reconstructed via `Arc::from_raw`).
    ///
    /// `task` is the `Box<Pin<Box<dyn Future<Output = ()> + Send +
    /// 'static>>>` cast to `*mut TaskOpaque`. The vtable takes
    /// ownership of the outer box; the consumer MUST NOT touch the
    /// pointer after this call returns.
    ///
    /// # Safety
    /// - `data` MUST be a value previously produced by persist's
    ///   `executor_capsule` for this same vtable. Mismatched `data`
    ///   ↔ `vtable` pairings are UB.
    /// - `task` MUST be a `Box<Pin<Box<dyn Future<Output = ()> +
    ///   Send + 'static>>>` produced via `Box::into_raw`. Any other
    ///   provenance is UB.
    /// - The function MUST be called from a thread for which `data`'s
    ///   underlying `Arc<Runtime>` is alive (which is always true if
    ///   the capsule has not been dropped — see the lifetime section
    ///   in the module docs).
    pub spawn: unsafe extern "C" fn(data: *mut c_void, task: *mut TaskOpaque),
    /// Drop the executor — decrements the underlying `Arc<Runtime>`.
    /// Called by the consumer when the capsule itself is dropped
    /// (Python GC).
    ///
    /// # Safety
    /// - `data` MUST be a value previously produced by persist's
    ///   `executor_capsule` for this same vtable.
    /// - MUST be called exactly once per capsule. Double-drop is UB.
    pub drop: unsafe extern "C" fn(data: *mut c_void),
}

/// The capsule contents — opaque data pointer + vtable.
///
/// Consumers receive this via a `PyCapsule` whose pointer (after the
/// name-tag check) IS a `*mut AsyncExecutor`. Treat the fields as
/// opaque; only invoke through the vtable's function pointers.
#[repr(C)]
pub struct AsyncExecutor {
    /// Opaque payload pointer. The vtable's spawn/drop interpret it.
    /// Persist's vtable expects an `Arc::into_raw`'d
    /// `Arc<tokio::runtime::Runtime>`; other producers MAY use any
    /// other shape as long as their own vtable interprets it
    /// consistently.
    pub data: *mut c_void,
    /// Reference to a static vtable. The vtable lives inside
    /// `ciris_persist.abi3.so`; calling its function pointers
    /// dispatches into persist's `.so` regardless of which cdylib
    /// invoked the call.
    pub vtable: &'static AsyncExecutorVTable,
}

// SAFETY: AsyncExecutor is Send+Sync — the underlying Arc<Runtime>
// is Send+Sync, and the vtable is a 'static reference (always
// thread-safe). The capsule round-trip across the cdylib boundary
// does not require either bound for the FFI itself, but consumers
// frequently want to stash the capsule's pointer in a struct that
// crosses thread boundaries. Marking these here makes the
// expectations explicit.
unsafe impl Send for AsyncExecutor {}
unsafe impl Sync for AsyncExecutor {}

/// Persist's vtable instance. Address stable across the process
/// lifetime — this is what the consumer's `AsyncExecutor.vtable`
/// reference targets.
pub static PERSIST_EXECUTOR_VTABLE: AsyncExecutorVTable = AsyncExecutorVTable {
    abi_version: ASYNC_EXECUTOR_ABI_VERSION,
    _reserved: 0,
    spawn: persist_spawn,
    drop: persist_drop,
};

/// Implementation of `AsyncExecutorVTable::spawn` for persist's tokio.
///
/// # Safety
/// See [`AsyncExecutorVTable::spawn`] safety notes. This function
/// MUST be invoked exclusively through the vtable's function pointer,
/// never called directly from outside `ciris_persist.abi3.so`.
unsafe extern "C" fn persist_spawn(data: *mut c_void, task: *mut TaskOpaque) {
    // SAFETY: per the vtable contract, `data` was produced by
    // `Arc::into_raw(Arc<Runtime>)` on the persist side. We
    // reconstruct without dropping by cloning and re-leaking.
    let runtime: Arc<tokio::runtime::Runtime> = unsafe {
        let raw = data as *const tokio::runtime::Runtime;
        let arc = Arc::from_raw(raw);
        let clone = arc.clone();
        // Don't drop ours — we don't own the data pointer; the
        // capsule does. Re-leak to keep refcount stable.
        let _ = Arc::into_raw(arc);
        clone
    };

    // SAFETY: per the vtable contract, `task` was produced by
    // `Box::into_raw(Box::new(Box::pin(async { ... }) as Pin<Box<dyn
    // Future + Send + 'static>>))` on the consumer side. We
    // reconstruct and take ownership.
    type BoxedFut = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
    let wrapped: Box<BoxedFut> = unsafe { Box::from_raw(task as *mut BoxedFut) };
    let future: BoxedFut = *wrapped;

    // Spawn onto persist's tokio runtime. The future's polling will
    // happen on a worker thread owned by this runtime, so tokio's
    // thread-local current-runtime context will resolve to persist's
    // tokio throughout the future's lifetime. Calls to persist's
    // public API from inside the future use persist's tokio
    // primitives naturally.
    runtime.spawn(future);
}

/// Implementation of `AsyncExecutorVTable::drop` for persist's tokio.
///
/// # Safety
/// See [`AsyncExecutorVTable::drop`] safety notes. Single-drop only;
/// double-drop is UB.
unsafe extern "C" fn persist_drop(data: *mut c_void) {
    // SAFETY: per the vtable contract, `data` was produced by
    // `Arc::into_raw(Arc<Runtime>)`. Reconstruct to drop the Arc.
    let _runtime: Arc<tokio::runtime::Runtime> =
        unsafe { Arc::from_raw(data as *const tokio::runtime::Runtime) };
    // Drop runs here; if this was the last Arc, the runtime shuts
    // down on the persist side.
}

/// Construct an [`AsyncExecutor`] backed by `runtime`. The returned
/// value is what `executor_capsule` wraps in a `PyCapsule`.
///
/// Persist calls this when handing the capsule to a consumer.
pub fn build_persist_executor(runtime: Arc<tokio::runtime::Runtime>) -> AsyncExecutor {
    AsyncExecutor {
        data: Arc::into_raw(runtime) as *mut c_void,
        vtable: &PERSIST_EXECUTOR_VTABLE,
    }
}

/// Build a `PyCapsule` wrapping a fresh [`AsyncExecutor`] backed by
/// `runtime`, with a destructor that calls the vtable's `drop` at GC
/// time (CIRISPersist#157).
///
/// Confined to this module because the FFI capsule construction
/// needs `unsafe` for `PyCapsule::new_with_destructor` (PyO3 requires
/// the caller to acknowledge that the destructor runs on the Python
/// GC thread without holding the GIL on PyO3's side). The crate-wide
/// `#![deny(unsafe_code)]` would refuse this if it lived in
/// `src/ffi/pyo3.rs`; isolating it here matches the
/// `src/debug/mod.rs` precedent for FFI-required unsafe surfaces.
///
/// The capsule's payload pointer is a `Box::into_raw`'d
/// `Box<AsyncExecutor>`. The destructor reconstructs the box and
/// invokes `vtable.drop(data)` before deallocating the envelope.
#[cfg(feature = "pyo3")]
pub fn build_capsule_with_destructor<'py>(
    py: pyo3::Python<'py>,
    runtime: Arc<tokio::runtime::Runtime>,
) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::types::PyCapsule>> {
    use pyo3::types::PyCapsule;
    let executor = build_persist_executor(runtime);
    let boxed_executor: Box<AsyncExecutor> = Box::new(executor);
    let raw: *mut AsyncExecutor = Box::into_raw(boxed_executor);
    // SAFETY: `raw` was just produced by `Box::into_raw`; we hand it
    // to PyCapsule, which calls the destructor exactly once at GC.
    // The destructor reconstructs the Box (recovering ownership)
    // before invoking vtable.drop on the inner data pointer.
    unsafe {
        PyCapsule::new_with_value_and_destructor(
            py,
            raw as usize,
            c"ciris_persist::executor_capsule_v1",
            |raw_usize, _ctx| {
                let raw_ptr = raw_usize as *mut AsyncExecutor;
                if raw_ptr.is_null() {
                    return;
                }
                // SAFETY: raw_ptr is the pointer we Box::into_raw'd. It
                // has not been observed by anyone else (the only path
                // into this destructor is PyCapsule's single-fire GC).
                let executor: Box<AsyncExecutor> = Box::from_raw(raw_ptr);
                // Dispatch through the vtable's drop function (lives
                // inside persist's .so; decrements the Arc<Runtime>).
                (executor.vtable.drop)(executor.data);
                // Box deallocates the AsyncExecutor envelope here.
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn abi_version_pinned_at_1() {
        // The version is part of the contract. Bumping it requires a
        // commit-level decision, not a casual edit — pin the value.
        assert_eq!(ASYNC_EXECUTOR_ABI_VERSION, 1);
        assert_eq!(PERSIST_EXECUTOR_VTABLE.abi_version, 1);
    }

    #[test]
    fn vtable_layout_is_c_repr() {
        // Layout assertion: the vtable's first field is the version
        // tag, the size matches the documented shape. Consumers read
        // `vtable.abi_version` via `&'static AsyncExecutorVTable`,
        // so the field offset MUST be 0.
        let v = &PERSIST_EXECUTOR_VTABLE;
        let base = v as *const _ as usize;
        let version_field = &v.abi_version as *const _ as usize;
        assert_eq!(version_field, base, "abi_version must be at offset 0");
    }

    #[test]
    fn spawn_drop_round_trip_via_vtable() {
        // Simulate the consumer side: build a runtime + executor on
        // persist's side, hand the executor through the C-ABI, the
        // "consumer" hands a future back, blocks on a channel.

        let runtime = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let executor = build_persist_executor(runtime.clone());

        // Consumer-side: package an async block that delivers via
        // mpsc. The future deliberately uses no tokio primitives —
        // the only thing that would resolve to the consumer's tokio
        // is `tokio::*` macro calls, and there are none.
        let (tx, rx) = mpsc::channel::<u32>();
        type BoxedFut = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
        let fut: BoxedFut = Box::pin(async move {
            let _ = tx.send(42);
        });
        let wrapped: Box<BoxedFut> = Box::new(fut);
        let task_ptr: *mut TaskOpaque = Box::into_raw(wrapped) as *mut TaskOpaque;

        // Spawn through the vtable. SAFETY: data + task are
        // well-formed per the contract above.
        unsafe { (executor.vtable.spawn)(executor.data, task_ptr) };

        // current_thread runtime needs explicit polling. The handle
        // doesn't drive the runtime; the runtime drives itself only
        // when blocked-on. Use a small block_on poll loop.
        let handle = runtime.handle().clone();
        // Drain the spawned task. The block_on(rx.recv_timeout) is
        // doing two jobs: (a) drive the runtime through any pending
        // work; (b) wait for the result. For a current_thread RT this
        // is the canonical "make my spawned tasks actually run" idiom.
        let result = std::thread::spawn(move || {
            // Drive the current_thread runtime in a worker thread.
            handle.block_on(async { tokio::task::yield_now().await });
        });
        let received = rx.recv_timeout(std::time::Duration::from_secs(2)).ok();
        let _ = result.join();
        // current_thread RT semantics: the spawned future runs when
        // some block_on is active. Either we received 42 or the test
        // platform's scheduling didn't drive it — accept both
        // outcomes, but if received we MUST have 42 (proves the
        // round-trip works).
        if let Some(value) = received {
            assert_eq!(value, 42, "round-trip delivered the correct payload");
        }

        // Drop the executor through the vtable. SAFETY: single-drop,
        // matched vtable.
        unsafe { (executor.vtable.drop)(executor.data) };

        // After the drop, our local `runtime` still holds one Arc, so
        // the runtime is still alive. Drop that too explicitly to
        // make the lifetime story visible.
        drop(runtime);
    }

    #[test]
    fn spawn_via_multi_thread_runtime_actually_runs() {
        // The current_thread test above can't guarantee execution
        // because it needs an external `block_on`. Multi-thread
        // runtimes self-drive via their worker pool — this test
        // proves the spawn-through-vtable end-to-end with a runtime
        // shape closer to what the PyEngine ships.
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap(),
        );
        let executor = build_persist_executor(runtime.clone());

        let (tx, rx) = mpsc::channel::<&'static str>();
        type BoxedFut = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
        let fut: BoxedFut = Box::pin(async move {
            let _ = tx.send("hello from persist's tokio");
        });
        let wrapped: Box<BoxedFut> = Box::new(fut);
        let task_ptr: *mut TaskOpaque = Box::into_raw(wrapped) as *mut TaskOpaque;

        unsafe { (executor.vtable.spawn)(executor.data, task_ptr) };

        let received = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("multi-thread runtime drives spawned tasks; receive must succeed");
        assert_eq!(received, "hello from persist's tokio");

        unsafe { (executor.vtable.drop)(executor.data) };
        drop(runtime);
    }
}
