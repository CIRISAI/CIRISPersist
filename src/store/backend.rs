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
    AuditEntry, ClaimParams, DeleteSummary, GraphNode, ServiceCorrelation, Task, TraceEventRow,
    TraceLlmCallRow,
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

    /// v0.1.17 — backend-side diagnostic for the verify-unknown-key
    /// breadcrumb (CIRISPersist#6). Returns total count of valid
    /// (unrevoked, unexpired) public-key rows + a sample of up to
    /// `limit` `key_id` values.
    ///
    /// Used ONLY by the `IngestPipeline` warn-log emitted when
    /// `lookup_public_key` returns `Ok(None)` — surfaces "what does
    /// the backend actually see at lookup time" so a verify miss can
    /// be triaged without source-level instrumentation. Default impl
    /// returns an empty sample (the Memory backend doesn't run a real
    /// query); the Postgres impl runs `SELECT COUNT(*) ... + LIMIT N`
    /// against `cirislens.accord_public_keys` with the same filter
    /// the runtime lookup applies.
    ///
    /// **Not part of the public ingest contract.** Don't make
    /// production decisions on this method's output; it's a
    /// diagnostic-only escape hatch.
    fn sample_public_keys(
        &self,
        limit: usize,
    ) -> impl Future<Output = Result<PublicKeySample, Error>> + Send {
        let _ = limit;
        async {
            Ok(PublicKeySample {
                size: 0,
                sample: Vec::new(),
            })
        }
    }

    /// Run pending migrations against the backend's schema. Phase 1
    /// migrations live in `migrations/postgres/lens/` and
    /// `migrations/sqlite/lens/`; the runner is `refinery`.
    fn run_migrations(&self) -> impl Future<Output = Result<(), Error>> + Send;

    /// v0.3.5 (CIRISLens#8 ASK 1) — GDPR Article 17 / DSAR primitive.
    /// Delete every persist-substrate row for `agent_id_hash`:
    ///
    /// - `trace_events` rows where `agent_id_hash` matches
    /// - `trace_llm_calls` rows joined by `trace_id` from the deleted
    ///   trace_events set (LLM call rows don't carry agent_id_hash
    ///   directly per V001 schema)
    ///
    /// When `include_federation_key=true`, additionally:
    ///
    /// - `federation_keys` rows where `identity_type='agent'` AND
    ///   `identity_ref=agent_id_hash`. May be >1 if the agent rotated
    ///   keys.
    /// - FK-cascade: `federation_attestations` rows referencing those
    ///   key_ids (attesting / attested / scrub_key_id) deleted first
    /// - FK-cascade: `federation_revocations` rows referencing those
    ///   key_ids deleted before the federation_keys delete
    ///
    /// All deletes happen in a single transaction. The caller's
    /// `agent_id_hash` is not validated against any signing-key
    /// proof — that's the lens's DSAR-orchestration responsibility.
    /// Persist owns the substrate row delete; lens owns the audit +
    /// signature verification of the request envelope.
    ///
    /// Idempotent: re-invocation on an already-deleted agent returns
    /// a `DeleteSummary` with all counts zero.
    fn delete_traces_for_agent(
        &self,
        agent_id_hash: &str,
        include_federation_key: bool,
    ) -> impl Future<Output = Result<DeleteSummary, Error>> + Send;

    /// v0.3.5 (CIRISLens#8 ASK 3) — Page-cursor read primitive for
    /// analytical streaming. Returns up to `limit` `trace_events` rows
    /// where `event_id > after_event_id`, ordered ascending by
    /// `event_id` (the BIGSERIAL primary key). Optional
    /// `agent_id_hash` filter.
    ///
    /// Caller orchestrates the cursor — track the max returned
    /// `event_id` between calls, pass it as `after_event_id` for the
    /// next page, stop when the result set is empty.
    ///
    /// Cleaner than a callback-style `iterate_trace_events(filter, cb)`
    /// across PyO3: callers pull pages on their own pace, no FFI
    /// re-entry per row, no shared-state synchronization. Same shape
    /// `Engine.run_pqc_sweep` uses (cursor at the trait boundary,
    /// caller drives).
    ///
    /// `event_id` is internal to the row but is returned in the
    /// `TraceEventRow` indirectly via the row's serialized form;
    /// the PyO3 surface (`Engine.fetch_trace_events_page`) returns
    /// dicts that include `event_id` so callers can extract the
    /// cursor without parsing further.
    fn fetch_trace_events_page(
        &self,
        after_event_id: i64,
        limit: i64,
        agent_id_hash: Option<&str>,
    ) -> impl Future<Output = Result<Vec<(i64, TraceEventRow)>, Error>> + Send;

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

/// v0.1.17 — diagnostic snapshot of `accord_public_keys` for the
/// verify-unknown-key breadcrumb. See [`Backend::sample_public_keys`].
///
/// Mission constraint: this is observability scaffolding, not a
/// production data path. The `sample` is bounded by the caller's
/// `limit` and is whatever the backend orders the rows by (no
/// stability guarantee across calls).
#[derive(Debug, Clone, Default)]
pub struct PublicKeySample {
    /// Total count of valid (unrevoked, unexpired) public-key rows
    /// the backend can see at the time of the call.
    pub size: usize,
    /// First N `key_id` values per the backend's natural ordering
    /// (typically primary-key order on Postgres).
    pub sample: Vec<String>,
}
