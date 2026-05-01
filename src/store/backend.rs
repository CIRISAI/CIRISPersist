//! Backend trait — sealed Phase 1, surfaces Phase 2 + 3 (stubbed
//! `unimplemented!()` until those phases land).
//!
//! # Mission alignment (MISSION.md §2 — `store/`)
//!
//! Same persistence trait surface, regardless of substrate. Phase 1's
//! Postgres impl satisfies the Phase-1 methods; Phase 2's expanded
//! impl fills in audit + correlation; Phase 3 finishes runtime state.
//! The trait surface itself is Phase 1 work — the lock-in that
//! prevents bifurcation between "Phase 1+2 ciris-persist" vs "Phase 3
//! ciris-persist" the FSD §5.2 calls out.
//!
//! Mission constraint (MISSION.md §3 anti-pattern #4): typed errors;
//! every fallible operation returns `Result<T, Error>` with a defined
//! `Error` variant, never panics in non-test code paths.

use std::future::Future;

use ed25519_dalek::VerifyingKey;

use super::types::{
    AuditEntry, ClaimParams, GraphNode, ServiceCorrelation, Task, TraceEventRow, TraceLlmCallRow,
};
use super::Error;

/// Persistence Backend trait — the load-bearing abstraction.
///
/// Async surface uses Rust 1.75+ `async fn in trait` directly; futures
/// are constrained `Send` so backends can be used from
/// `tokio::spawn`-style multi-threaded contexts.
///
/// Phase 1 methods are ready to implement. Phase 2 / 3 methods are
/// part of the Phase 1 trait shape but their default impl returns an
/// `Error::NotImplemented` — a backend that doesn't yet support a
/// surface returns that variant rather than panicking, so callers
/// can handle "this backend can't do that" as a typed error.
pub trait Backend: Send + Sync {
    // ─── Phase 1 — lens trace ingest ───────────────────────────────

    /// Insert a batch of `trace_events` rows. Returns the count of
    /// rows actually inserted (i.e. excluding ON CONFLICT skips).
    ///
    /// Mission constraint (MISSION.md §4 "Idempotency"): adapter
    /// retries are safe; conflict on
    /// `(trace_id, thought_id, event_type, attempt_index)` is a
    /// no-op.
    fn insert_trace_events_batch(
        &self,
        rows: &[TraceEventRow],
    ) -> impl Future<Output = Result<InsertReport, Error>> + Send;

    /// Insert a batch of `trace_llm_calls` rows. Returns the count of
    /// rows actually inserted.
    fn insert_trace_llm_calls_batch(
        &self,
        rows: &[TraceLlmCallRow],
    ) -> impl Future<Output = Result<usize, Error>> + Send;

    /// Look up a verifying key by `signature_key_id`
    /// (`accord_public_keys` table).
    fn lookup_public_key(
        &self,
        key_id: &str,
    ) -> impl Future<Output = Result<Option<VerifyingKey>, Error>> + Send;

    /// Run pending migrations against the backend's schema. Phase 1
    /// migrations live in `migrations/postgres/lens/` and
    /// `migrations/sqlite/lens/`; the runner is `refinery`.
    fn run_migrations(&self) -> impl Future<Output = Result<(), Error>> + Send;

    // ─── Phase 2 — agent signed-events + TSDB (FSD §4) ─────────────

    /// Append an entry to the agent's `audit_log`. Phase 2 surface;
    /// default returns `NotImplemented` until the agent flips to
    /// the crate.
    fn append_audit_entry(
        &self,
        _entry: &AuditEntry,
    ) -> impl Future<Output = Result<i64, Error>> + Send {
        async { Err(Error::NotImplemented("append_audit_entry (Phase 2)")) }
    }

    /// Record a service correlation (TSDB row). Phase 2 surface.
    fn record_correlation(
        &self,
        _c: &ServiceCorrelation,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        async { Err(Error::NotImplemented("record_correlation (Phase 2)")) }
    }

    // ─── Phase 3 — runtime state, memory graph, governance ─────────

    /// Upsert a task (FSD §5.1). Phase 3 surface.
    fn upsert_task(&self, _t: &Task) -> impl Future<Output = Result<(), Error>> + Send {
        async { Err(Error::NotImplemented("upsert_task (Phase 3)")) }
    }

    /// `try_claim_shared_task` race-claim (FSD §5.6).
    /// Returns `(task, was_created)` matching the existing Python
    /// signature. Phase 3 surface.
    fn try_claim_shared_task(
        &self,
        _params: ClaimParams<'_>,
    ) -> impl Future<Output = Result<(Task, bool), Error>> + Send {
        async { Err(Error::NotImplemented("try_claim_shared_task (Phase 3)")) }
    }

    /// Add a graph node (FSD §5.1).
    /// Phase 3 surface; the encryption boundary stays *above* the
    /// persistence layer — this method receives ciphertext as opaque
    /// JSONB (FSD §5.7).
    fn add_graph_node(&self, _n: &GraphNode) -> impl Future<Output = Result<(), Error>> + Send {
        async { Err(Error::NotImplemented("add_graph_node (Phase 3)")) }
    }
}

/// Report of a batch insert.
///
/// Mission category §4 "Idempotency": separates inserted from
/// conflicted so callers can tell whether retries actually wrote new
/// rows or merely confirmed existing ones.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InsertReport {
    /// Number of rows that were newly inserted.
    pub inserted: usize,
    /// Number of rows that hit `ON CONFLICT DO NOTHING` (idempotent
    /// re-submission).
    pub conflicted: usize,
}

impl InsertReport {
    /// Total rows considered by the backend (inserted + conflicted).
    pub fn total_seen(&self) -> usize {
        self.inserted + self.conflicted
    }
}
