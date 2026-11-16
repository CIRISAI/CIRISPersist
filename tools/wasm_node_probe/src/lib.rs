//! v62.0.0 (slice D, P12) — the wasm node probe. See `Cargo.toml`.
//!
//! `init` installs persist's host seams over the ABI (the single-thread
//! executor profile, [`AbiClock`]); `api` opens an in-memory SQLite store and
//! runs every persist migration, polled to completion on this one thread, so
//! the module links the store, the migration set and the SQLite build that
//! a browser or EFI node runs. The import gate reads what that costs.
//!
//! The `unsafe` here is the C ABI sqlite-wasm-rs requires of the module
//! (`#[no_mangle] extern "C"` hooks); persist itself stays
//! `#![deny(unsafe_code)]`.

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use ciris_host_abi::{clock, random, Event, Node};
use ciris_persist::host::abi::AbiClock;
use ciris_persist::store::Backend as _;

struct Probe;

/// Poll `fut` to completion on this thread (the single-thread profile runs
/// blocking work inline, so nothing here waits on another task).
fn run<F: Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

impl Node for Probe {
    fn init() -> Result<(), String> {
        ciris_persist::host::HostSeams::single_thread()
            .with_clock(Arc::new(AbiClock))
            .install();
        Ok(())
    }

    fn tick(_budget_us: u32) -> u64 {
        clock::monotonic_us() + 1_000_000
    }

    fn on_event(_e: Event) {}

    fn api(_req: Vec<u8>, _local: bool) -> Vec<u8> {
        let outcome = run(async {
            let backend = ciris_persist::store::SqliteBackend::open_in_memory().await?;
            backend.run_migrations().await
        });
        match outcome {
            Ok(()) => b"ok".to_vec(),
            Err(e) => format!("err: {e}").into_bytes(),
        }
    }
}

ciris_host_abi::export_node!(Probe);

// ── sqlite-wasm-rs's link-time host hooks, over the ciris:node imports ──

/// Status codes (`sqlite_wasm_rs::host::OK` / `Error::Unsupported`).
const OK: i32 = 0;
const UNSUPPORTED: i32 = 1;

#[no_mangle]
pub extern "C" fn rust_sqlite_wasm_host_sleep(_seconds: u64, _nanoseconds: u32) {
    // One thread, no blocking sleep: SQLite's busy handler retries at once.
}

/// # Safety
/// `buf` is valid for `len` bytes (sqlite-wasm-rs's contract).
#[no_mangle]
pub unsafe extern "C" fn rust_sqlite_wasm_host_random(buf: *mut u8, len: usize) -> usize {
    let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    random::fill_bytes(out);
    len
}

/// # Safety
/// `out` is a valid `i64` (sqlite-wasm-rs's contract).
#[no_mangle]
pub unsafe extern "C" fn rust_sqlite_wasm_host_epoch_timestamp_in_ms(out: *mut i64) -> i32 {
    match clock::wall_ms() {
        Some(ms) => {
            unsafe { *out = ms };
            OK
        }
        None => UNSUPPORTED,
    }
}

/// # Safety
/// `buf` is valid for `len` bytes (sqlite-wasm-rs's contract).
#[no_mangle]
pub unsafe extern "C" fn rust_sqlite_wasm_host_fill_entropy(buf: *mut u8, len: usize) -> i32 {
    let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    random::fill_bytes(out);
    OK
}

/// No `localtime` on a node (persist's migrations use none: UTC only).
#[no_mangle]
pub extern "C" fn rust_sqlite_wasm_host_localtime(_unix_seconds: i64, _out: *mut u8) -> i32 {
    UNSUPPORTED
}
