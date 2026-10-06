//! v53.1.5 — **the attestation read probe**, test-only.
//!
//! Every backend's attestation-returning read records `(method, key, rows
//! returned, envelope bytes returned)` here, on the CURRENT THREAD, so a
//! witness on any backend can assert what a door read and how much — the
//! memory backend's per-method counters cannot say WHICH key was read, and
//! the steward fold legitimately reads the SUBJECT's slice on the same path
//! that must not read the TARGET's. Thread-local because the harness runs
//! tests in parallel; `#[tokio::test]` is current-thread, and each backend
//! records in its trait method body (not inside a blocking dispatch), so a
//! test sees exactly its own reads.
//!
//! Bytes are the serialized envelope length — what a row costs to decode
//! and hold, which is what the canonical's heap scaled with (agent-authored
//! envelopes average 15.3 KB; 2,461 rows about canonical-1).

use std::cell::RefCell;

/// One recorded read.
#[derive(Debug, Clone)]
pub struct Read {
    /// The directory method.
    pub method: &'static str,
    /// The key the read was pinned on (attested, attesting, or `*`).
    pub key: String,
    /// Rows returned.
    pub rows: usize,
    /// Serialized envelope bytes returned.
    pub bytes: usize,
}

thread_local! {
    static READS: RefCell<Vec<Read>> = const { RefCell::new(Vec::new()) };
}

/// Record one read: `method` over `key`, returning `rows`.
pub fn record(method: &'static str, key: &str, rows: &[crate::federation::Attestation]) {
    let bytes = rows
        .iter()
        .map(|a| {
            serde_json::to_string(&a.attestation_envelope)
                .map(|s| s.len())
                .unwrap_or(0)
        })
        .sum();
    READS.with(|r| {
        r.borrow_mut().push(Read {
            method,
            key: key.to_owned(),
            rows: rows.len(),
            bytes,
        });
    });
}

/// Take (and clear) this thread's recorded reads.
#[must_use]
pub fn take() -> Vec<Read> {
    READS.with(|r| std::mem::take(&mut *r.borrow_mut()))
}
