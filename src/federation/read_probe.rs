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
    /// Serialized envelope bytes of the rows the read decoded: the rows it
    /// returned, plus (for a typed bounded read) the one lookahead row
    /// fetched past the page.
    pub bytes: usize,
    /// v56.0.0 (CIRISPersist#1001) — for a typed bounded read
    /// (`attestation_query`), the query as it ran; `None` for every other
    /// door.
    pub query: Option<crate::federation::attestation_query::AttestationQuery>,
}

impl Read {
    /// v56.0.0 (CIRISPersist#1001) — the door this read answers as: a
    /// non-query read is its own method; a typed query answers as the read it
    /// replaced ([`AttestationQuery::shape`]), so a witness that asks "did
    /// this fold read K's whole slice?" keeps asking it after the fold moved
    /// onto the query.
    ///
    /// [`AttestationQuery::shape`]: crate::federation::attestation_query::AttestationQuery::shape
    #[must_use]
    pub fn door(&self) -> &'static str {
        match &self.query {
            None => self.method,
            Some(q) => q.shape(),
        }
    }

    /// The key the [`Self::door`] read was pinned on: the attested key for a
    /// `for` door, the attester for a `by` door.
    #[must_use]
    pub fn door_key(&self) -> &str {
        match &self.query {
            None => &self.key,
            Some(q) => q.to.as_deref().or(q.by.as_deref()).unwrap_or("*"),
        }
    }

    /// Whether this read answers as `door` over `key`.
    #[must_use]
    pub fn is(&self, door: &str, key: &str) -> bool {
        self.door() == door && self.door_key() == key
    }

    /// Whether this read starts a walk: every non-query read, and a query's
    /// first page (no cursor).
    #[must_use]
    pub fn is_first_page(&self) -> bool {
        self.query.as_ref().is_none_or(|q| q.after.is_none())
    }

    /// Whether this read is a whole-slice read (`list_attestations_by` /
    /// `_for`, or a query that answers as one) over any key.
    #[must_use]
    pub fn is_slice_read(&self) -> bool {
        matches!(
            self.door(),
            "list_attestations_by" | "list_attestations_for"
        )
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
///
/// `fetched` is every row the backend decoded, the lookahead row past the
/// page included; `returned` is how many the page serves. `rows` records
/// `returned`; `bytes` sizes all of `fetched`, the same rows the counters'
/// decode-cost bytes cover, measured independently (re-serialized here,
/// stored TEXT length there).
pub fn record_query(
    q: &crate::federation::attestation_query::AttestationQuery,
    fetched: &[crate::federation::Attestation],
    returned: usize,
) {
    let bytes = fetched
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
            rows: returned,
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
