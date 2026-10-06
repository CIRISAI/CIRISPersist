//! v53.1.5 — **the whole-slice read probe**, test-only.
//!
//! Every backend's `list_attestations_for` / `list_attestations_by` records
//! `(method, key, rows returned)` here, on the CURRENT THREAD, so a witness
//! on any backend can assert that a door did not read a key's whole slice —
//! the memory backend's per-method counters cannot say WHICH key was read,
//! and the steward fold legitimately reads the SUBJECT's slice on the same
//! path that must not read the TARGET's. Thread-local because the harness
//! runs tests in parallel; `#[tokio::test]` is current-thread, and each
//! backend records in its trait method body (not inside a blocking
//! dispatch), so a test sees exactly its own reads.

use std::cell::RefCell;

thread_local! {
    static READS: RefCell<Vec<(&'static str, String, usize)>> = const { RefCell::new(Vec::new()) };
}

/// Record one whole-slice read: `method` over `key`, returning `rows` rows.
pub fn record(method: &'static str, key: &str, rows: usize) {
    READS.with(|r| r.borrow_mut().push((method, key.to_owned(), rows)));
}

/// Take (and clear) this thread's recorded reads.
#[must_use]
pub fn take() -> Vec<(&'static str, String, usize)> {
    READS.with(|r| std::mem::take(&mut *r.borrow_mut()))
}
