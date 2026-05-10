//! Federation read primitives — typed read surface for lens, lens-core,
//! and sovereign-mode agents (v0.5.0+, CIRISPersist#23).
//!
//! # Mission alignment (MISSION.md §2 — `read/`)
//!
//! Persist holds the substrate; consumers compose policy. This module
//! defines the [`ReadEngine`] trait — typed read primitives covering
//! the surfaces lens, lens-core, and sovereign-mode agents need to
//! retire the historical `cirislens_reader` direct-SQL carve-out
//! ([`crate::store::Backend::fetch_trace_events_page`] docstring names
//! that carve-out; v0.5.0 onward replaces it).
//!
//! ## Surface duality (CIRISPersist v0.4.1 precedent)
//!
//! Each primitive lands as **both**:
//!
//! - **Rust-public**: trait method on [`ReadEngine`] (this file) +
//!   re-exported through [`crate::prelude`]. Lens-core (Rust rlib path)
//!   and sovereign-mode agents (in-process Rust) consume these directly.
//! - **PyO3**: thin wrapper on `Engine` (lens FastAPI / sovereign-mode
//!   Python path). Same shape `verify_hybrid_via_directory` established
//!   in v0.4.1.
//!
//! Single source of truth — no Python-only reimplementation drifting
//! from Rust.
//!
//! ## Audience
//!
//! Three consumer tiers, all with the same surface:
//!
//! 1. **Lens API (Python, PyO3 path)** — drives `/repository/traces`,
//!    `/coherence-ratchet/*`, scoring endpoints, dashboards.
//! 2. **CIRISLensCore (Rust rlib path)** — same primitives, same single-
//!    source-of-truth pattern.
//! 3. **Sovereign-mode agents (PyO3 self-read)** — compute their own
//!    scores locally, observe their own drift, verify their own peers.
//!    No centralization assumed.
//!
//! ## v0.5.0 scope
//!
//! Sections A (trace listing) + B (trace detail) + F (Coherence Ratchet
//! inputs) + E (scoring factor aggregates), per
//! `FSD/V0_5_0_FEDERATION_READ_PRIMITIVES.md`. Sections C / D / G / H / I
//! ship in v0.5.1 after lens validates the v0.5.0 batch in production.
//!
//! ## Cursor pagination contract
//!
//! All list primitives return [`TraceCursor`]-backed pages. No
//! `OFFSET/LIMIT`. Same shape v0.2.0's
//! [`crate::store::Backend::fetch_trace_events_page`] established for
//! per-row cursors; the read primitives use `(ts, trace_id)` tuple
//! cursors for per-trace ordering.
//!
//! ## Threat-model invariants
//!
//! - **AV-9 (cross-agent dedup)** — every trace-scoped read carries
//!   `agent_id_hash` in the result so callers can authorize at their
//!   layer. A malicious peer cannot read another peer's traces via
//!   `trace_id` alone.
//! - **AV-15 (FFI sanitization)** — error kinds use closed-set
//!   `&'static str` tokens; no attacker-controlled strings cross the
//!   boundary.
//! - **AV-43 (read-side adversary)** — added to THREAT_MODEL.md in
//!   v0.5.0. Aggregates return computed statistics, not per-trace
//!   content; smallest-window callers apply k-anonymity policy at
//!   their layer.

use std::future::Future;

pub mod scoring;
pub mod trace;
pub mod types;

pub use scoring::{AuditChainAggregate, RecoveryEvent, ScoringFactorAggregate};
pub use trace::{
    DivergenceRow, HashChainGap, OverrideRateRow, TemporalDriftRow, TraceComponentRow, TraceDetail,
    TraceEnvelopeRefs, TraceListPage, TraceSummary,
};
pub use types::{DeviationMetric, TimeWindow, TraceCursor, TraceFilter};

/// Federation read primitives — typed read surface lens / lens-core /
/// sovereign agents consume.
///
/// Every method is async; the futures are constrained `Send` so backends
/// can be used from `tokio::spawn`-style multi-threaded contexts (matches
/// [`crate::store::Backend`] / [`crate::federation::FederationDirectory`]
/// / [`crate::derived::DerivedSchema`] convention).
///
/// Backends that don't implement a given primitive (Memory backend for
/// most SQL-heavy aggregates; SQLite for the v0.5.0 batch) return
/// [`Error::NotImplemented`] rather than panicking — callers handle
/// "this backend can't do that" as a typed error.
pub trait ReadEngine: Send + Sync {
    // ── Section A — Trace listing (CIRISPersist#23 §A) ─────────────

    /// Page through trace summaries. Each [`TraceSummary`] is one row
    /// per `trace_id` with denormalized DMA / conscience / action /
    /// cost fields synthesized from the trace's component rows.
    ///
    /// Drives `/repository/traces`, dashboards, scoring corpus filters.
    /// Cursor-paged; no OFFSET/LIMIT.
    fn list_trace_summaries(
        &self,
        filter: TraceFilter,
        cursor: Option<TraceCursor>,
        limit: i64,
    ) -> impl Future<Output = Result<TraceListPage, Error>> + Send;

    /// Single-trace summary lookup. Returns `None` if the trace_id
    /// isn't in the backing store.
    fn get_trace_summary(
        &self,
        trace_id: &str,
    ) -> impl Future<Output = Result<Option<TraceSummary>, Error>> + Send;

    // ── Section B — Trace detail (CIRISPersist#23 §B) ──────────────

    /// Full trace reconstruction: summary + all per-component data
    /// (ordered by `ts`) + LLM call rows (chronological) + the
    /// envelope-level scrub + signature refs.
    ///
    /// Drives `/repository/traces/{trace_id}` and trace-detail
    /// explorers. Single round-trip; not paged (one trace fits in
    /// one round-trip per spec).
    fn get_trace_detail(
        &self,
        trace_id: &str,
    ) -> impl Future<Output = Result<Option<TraceDetail>, Error>> + Send;

    // ── Section F — Coherence Ratchet inputs (CIRISPersist#23 §F) ──

    /// Cross-agent divergence z-scores within a deployment domain.
    /// Lens computes detection from these inputs; persist provides
    /// the windowed peer-mean reference.
    fn cross_agent_divergence(
        &self,
        deployment_domain: &str,
        window: TimeWindow,
        metric: DeviationMetric,
    ) -> impl Future<Output = Result<Vec<DivergenceRow>, Error>> + Send;

    /// Temporal drift between a baseline window and a comparison
    /// window for a single agent. Returns one row per metric.
    fn temporal_drift(
        &self,
        agent_id_hash: &str,
        baseline: TimeWindow,
        comparison: TimeWindow,
    ) -> impl Future<Output = Result<Vec<TemporalDriftRow>, Error>> + Send;

    /// Hash-chain gaps over a window — sequence-number discontinuities
    /// in the agent's audit_log timeline. Each gap is `(start, end)`.
    fn hash_chain_gaps(
        &self,
        agent_id_hash: &str,
        window: TimeWindow,
    ) -> impl Future<Output = Result<Vec<HashChainGap>, Error>> + Send;

    /// Conscience-override rates per agent within a deployment domain,
    /// with the domain-average reference for ratio computation.
    fn conscience_override_rates(
        &self,
        deployment_domain: &str,
        window: TimeWindow,
    ) -> impl Future<Output = Result<Vec<OverrideRateRow>, Error>> + Send;

    // ── Section E — Scoring factor aggregates (CIRISPersist#23 §E) ─

    /// One bundled aggregate primitive returning everything any
    /// single CIRIS Capacity Score factor calculation needs in one
    /// DB round-trip. Composes the granular sub-primitives below.
    ///
    /// `baseline_window` is optional — when provided, the
    /// `drift_z_score` field is computed against the baseline; when
    /// absent, drift is `None`.
    fn aggregate_scoring_factors(
        &self,
        agent_id_hash: &str,
        window: TimeWindow,
        baseline_window: Option<TimeWindow>,
    ) -> impl Future<Output = Result<ScoringFactorAggregate, Error>> + Send;

    /// Batch variant: fleet-wide score sweep in one round-trip.
    /// Returns one [`ScoringFactorAggregate`] per agent in input order.
    fn aggregate_scoring_factors_batch(
        &self,
        agent_id_hashes: &[String],
        window: TimeWindow,
        baseline_window: Option<TimeWindow>,
    ) -> impl Future<Output = Result<Vec<ScoringFactorAggregate>, Error>> + Send;

    /// Granular: count traces matching a filter. Used by analysts
    /// composing narrower questions than the bundled aggregate.
    fn count_traces(&self, filter: TraceFilter) -> impl Future<Output = Result<i64, Error>> + Send;

    /// Granular: count conscience overrides matching a filter.
    fn count_overrides(
        &self,
        filter: TraceFilter,
    ) -> impl Future<Output = Result<i64, Error>> + Send;

    /// Granular: count identity changes (agent_id_hash transitions
    /// per agent_name) matching a filter.
    fn count_identity_changes(
        &self,
        filter: TraceFilter,
    ) -> impl Future<Output = Result<i64, Error>> + Send;

    /// Granular: audit-chain aggregate (total signed entries +
    /// detected gaps) for a filter window.
    fn aggregate_audit_chain(
        &self,
        filter: TraceFilter,
    ) -> impl Future<Output = Result<AuditChainAggregate, Error>> + Send;
}

/// Read-primitive errors. Distinct from [`crate::store::Error`] — read
/// primitives have their own typed failure surface for cursor parse,
/// invalid window, etc.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments (malformed cursor, inverted
    /// time window, empty agent_id_hash list, negative limit, etc.).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Cursor failed to parse / is from an incompatible version.
    #[error("invalid cursor: {0}")]
    InvalidCursor(String),

    /// Backend-level error (DB connection, serialization, etc.).
    /// String-typed because each backend has its own error tree.
    #[error("backend: {0}")]
    Backend(String),

    /// Surface declared on the trait but the backend doesn't yet
    /// implement it. Memory + Phase-1 SQLite return this for the
    /// SQL-heavy primitives.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    /// THREAT_MODEL.md AV-15: this is what crosses HTTP / PyO3
    /// boundaries; verbose `Display` form goes to tracing only.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "read_invalid_argument",
            Error::InvalidCursor(_) => "read_invalid_cursor",
            Error::Backend(_) => "read_backend",
            Error::NotImplemented(_) => "read_not_implemented",
        }
    }
}
