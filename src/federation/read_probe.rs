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
    /// v56.0.0 (CIRISPersist#1001) — for a typed bounded read
    /// (`attestation_query`), the query as it ran; `None` for every other
    /// door.
    pub query: Option<crate::federation::attestation_query::AttestationQuery>,
}

impl Read {
    /// Whether this read is a typed query pinned on `key` (as attester or
    /// attested) that does not narrow below the key's whole slice — the
    /// read the retired `list_attestations_by` / `_for` made, one page of it.
    #[must_use]
    pub fn is_slice_read_of(&self, key: &str) -> bool {
        self.query.as_ref().is_some_and(|q| {
            !q.is_narrowed() && (q.by.as_deref() == Some(key) || q.to.as_deref() == Some(key))
        })
    }

    /// Whether this read is a typed query pinned on `key` as ATTESTER and
    /// not narrowed (one page of the retired `list_attestations_by(key)`).
    #[must_use]
    pub fn is_by_slice_of(&self, key: &str) -> bool {
        self.query
            .as_ref()
            .is_some_and(|q| !q.is_narrowed() && q.by.as_deref() == Some(key))
    }

    /// Whether this read is a typed query pinned on `key` as ATTESTED and
    /// not narrowed (one page of the retired `list_attestations_for(key)`).
    #[must_use]
    pub fn is_for_slice_of(&self, key: &str) -> bool {
        self.query
            .as_ref()
            .is_some_and(|q| !q.is_narrowed() && q.to.as_deref() == Some(key))
    }
}

thread_local! {
    static READS: RefCell<Vec<Read>> = const { RefCell::new(Vec::new()) };
}

/// Record one read: `method` over `key`, returning `rows`. Called only from
/// [`crate::observe::record_read`], the one helper every door feeds.
pub fn record<R: crate::observe::ReadRow>(method: &'static str, key: &str, rows: &[R]) {
    let bytes = rows
        .iter()
        .map(|a| {
            serde_json::to_string(&a.attestation().attestation_envelope)
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
            query: None,
        });
    });
}

/// v56.0.0 (CIRISPersist#1001) — record one typed bounded read, with its
/// query. Called only from [`crate::observe::record_query_read`], which the
/// shared wrapper calls once per query.
pub fn record_query(
    q: &crate::federation::attestation_query::AttestationQuery,
    rows: &[crate::federation::Attestation],
) {
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
            method: crate::observe::Door::AttestationQuery.label(),
            key: q.key().to_owned(),
            rows: rows.len(),
            bytes,
            query: Some(q.clone()),
        });
    });
}

/// Take (and clear) this thread's recorded reads.
#[must_use]
pub fn take() -> Vec<Read> {
    READS.with(|r| std::mem::take(&mut *r.borrow_mut()))
}
