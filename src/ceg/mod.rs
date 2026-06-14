//! CEG (Coherence Epistemic Graph) read surface — typed read primitives
//! for lens, lens-core, and sovereign-mode agents (v0.5.0+,
//! CIRISPersist#23).
//!
//! # v4.0 reorganization (FSD §3)
//!
//! v4.0 rehomes the v3.x `src/read/` modules under topic-named `ceg/`
//! namespaces. This commit (the "module reorg" cut) is a **pure
//! mechanical move + re-export** — no behaviour change. The flat
//! re-exports below preserve every type the v3.x surface exposed, and
//! `crate::read` remains a thin façade shim that re-exports this module
//! so existing `crate::read::*` / `ciris_persist::read::*` import paths
//! still resolve. The CallerScope / Filter / Aggregate / Cache
//! primitives the FSD §4–§7 describe land in LATER v4.0 commits.
//!
//! Topic axis ages better than version axis as the CEG accumulates —
//! CEG version provenance lives in each module's header doc + `git log`,
//! not in directory names (FSD §3.1).
//!
//! # Mission alignment (MISSION.md §2 — read surface)
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
//! ## Scope by release
//!
//! - **v0.5.0** — Sections A (trace listing) + B (trace detail) +
//!   F (Coherence Ratchet inputs) + E (scoring factor aggregates),
//!   per `FSD/V0_5_0_FEDERATION_READ_PRIMITIVES.md`.
//! - **v0.5.5** — Remaining sections from CIRISPersist#23: C (task-
//!   grouped listing), D (LLM call surface), G (corpus shape),
//!   H (privacy / scrub observability), I (federation observability
//!   bulk lists). Additive only; no schema changes. Issue closed.
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

use crate::scope::CallerScope;

// ── Topic namespaces (FSD §3.1) ────────────────────────────────────

pub mod aggregates;
pub mod list;
pub mod types;

// Placeholder topic homes — staked out this commit so later v4.0 cuts
// (CallerScope predicate, identity/family/community reads, streaming,
// the structural-invisibility gate) have a module to land in.
pub mod cohort_scope;
pub mod community;
pub mod family;
pub mod identity;
pub mod streaming;
pub mod structural_invisibility;

// ── Flat re-exports (FSD §3.2 — the surface consumers use) ──────────
//
// The topic subpath documents subject area; this flat re-export is the
// public surface. These names match the v3.x `crate::read::*` exports
// exactly so the move is behaviour-neutral.

pub use aggregates::corpus::{CorpusShape, CorpusShapeFilter};
pub use aggregates::llm::{
    AgentCostStats, DomainCostStats, LlmCostAggregate, ModelCostStats, TotalCostStats,
};
pub use aggregates::repository::{
    ActionAggregates, ConscienceAggregates, ConsciencePerCheck, DomainBreakdown,
    FragilityAggregates, RepositoryFilter, RepositoryStatistics, ScoreAggregates,
    ScoreDistribution, Totals, REPOSITORY_STATISTICS_METHOD_ID,
};
pub use aggregates::scoring::{
    AuditChainAggregate, CoherencePoint, DivergenceRow, HashChainGap, OverrideRateRow,
    RecoveryEvent, ScoringFactorAggregate, StreamSummary, TemporalDriftRow,
};
pub use aggregates::scrub::ScrubAggregate;
pub use list::federation::{
    AttestationCursor, AttestationFilter, AttestationListPage, FederationKeyCursor,
    FederationKeyFilter, FederationKeyListPage, RevocationCursor, RevocationFilter,
    RevocationListPage,
};
pub use list::llm::{LlmCallCursor, LlmCallFilter, LlmCallListPage};
pub use list::tasks::{TaskClass, TaskCursor, TaskFilter, TaskGroup, TaskListPage};
pub use list::traces::{
    TraceComponentRow, TraceDetail, TraceEnvelopeRefs, TraceListPage, TraceSummary,
};
pub use types::{Aggregate, DeviationMetric, Filter, TimeWindow, TraceCursor, TraceFilter};

/// Federation read primitives — typed read surface lens / lens-core /
/// sovereign agents consume.
///
/// Every method is async; the futures are constrained `Send` so backends
/// can be used from `tokio::spawn`-style multi-threaded contexts (matches
/// [`crate::store::Backend`] / [`crate::federation::FederationDirectory`]
/// / [`crate::derived::DerivedSchema`] convention).
///
/// # v4.0 — scope-aware reads (FSD §8)
///
/// Every method takes a trailing [`CallerScope`] (FSD §8.1). The
/// [`CallerScope`] is a *load-bearing argument*: read methods whose
/// query touches a cohort-scoped table (`trace_events` via its
/// `cohort_scope` / `cohort_target_id` columns; `federation_attestations`
/// via `cohort_scope` / `attested_key_id`) AND-compose the §4.3
/// [`cohort_scope_sql_predicate`](crate::scope::cohort_scope_sql_predicate)
/// into their WHERE so suppressed rows never leave the backend (Layer 1
/// of the §9 defense-in-depth). Methods reading non-cohort-scoped tables
/// (the pure `federation_keys` / `federation_revocations` lists, the
/// audit-chain-gap reads keyed by `agent_id_hash`) accept `scope` and
/// apply the existing agent-ownership / AV-9 authorization model; for
/// those the predicate is a documented no-op in v4.0.
///
/// Both backends implement every method (MISSION §1.5 / anti-pattern
/// #4). There is no `NotImplemented` escape hatch — backend-shape
/// differences (Postgres CTE vs SQLite correlated subquery) are
/// implementation details, not error states (FSD §8.2).
///
/// Internal scope-bypassed reads (cache miss-path, integrity checks,
/// write-path-internal lookups) plumb through `pub(crate)` `*_internal`
/// siblings on the concrete backends (FSD §8.1), NOT a third
/// [`CallerScope`] variant.
pub trait ReadEngine: Send + Sync {
    // ── Section A — Trace listing (CIRISPersist#23 §A) ─────────────

    /// Page through trace summaries. Each [`TraceSummary`] is one row
    /// per `trace_id` with denormalized DMA / conscience / action /
    /// cost fields synthesized from the trace's component rows.
    ///
    /// Drives `/repository/traces`, dashboards, scoring corpus filters.
    /// Cursor-paged; no OFFSET/LIMIT. Scope-gated (§4.3) on
    /// `trace_events.cohort_scope` / `cohort_target_id`.
    fn list_trace_summaries(
        &self,
        filter: TraceFilter,
        cursor: Option<TraceCursor>,
        limit: i64,
        scope: CallerScope,
    ) -> impl Future<Output = Result<TraceListPage, Error>> + Send;

    /// Single-trace summary lookup. Returns `None` if the trace_id
    /// isn't in the backing store *or is not visible to `scope`*.
    fn get_trace_summary(
        &self,
        trace_id: &str,
        scope: CallerScope,
    ) -> impl Future<Output = Result<Option<TraceSummary>, Error>> + Send;

    // ── Section B — Trace detail (CIRISPersist#23 §B) ──────────────

    /// Full trace reconstruction: summary + all per-component data
    /// (ordered by `ts`) + LLM call rows (chronological) + the
    /// envelope-level scrub + signature refs.
    ///
    /// Drives `/repository/traces/{trace_id}` and trace-detail
    /// explorers. Single round-trip; not paged (one trace fits in
    /// one round-trip per spec). Scope-gated on the trace's
    /// `cohort_scope` / `cohort_target_id`.
    fn get_trace_detail(
        &self,
        trace_id: &str,
        scope: CallerScope,
    ) -> impl Future<Output = Result<Option<TraceDetail>, Error>> + Send;

    // ── Section C — Task-grouped listing (CIRISPersist#23 §C) ──────

    /// Page through tasks, each task carrying its component traces.
    /// Drives task-axis views (qa-eval / discord / wakeup-ritual /
    /// real-user pages) where the visible-page axis is task, not trace.
    ///
    /// Task ordering: `earliest_at DESC, task_id DESC` (newest-first
    /// triage). Trace ordering within a task: `thought_depth ASC`
    /// then `started_at ASC`. Cursor-paged; no OFFSET/LIMIT.
    ///
    /// `task_class` derivation is canonical via [`TaskClass::from_task_id`]
    /// — every federation peer sees the same class for a given task_id.
    /// Scope-gated on `trace_events.cohort_scope` / `cohort_target_id`.
    fn list_tasks(
        &self,
        filter: TaskFilter,
        cursor: Option<TaskCursor>,
        limit: i64,
        scope: CallerScope,
    ) -> impl Future<Output = Result<TaskListPage, Error>> + Send;

    // ── Section D — LLM call surface (CIRISPersist#23 §D) ──────────

    /// Page through LLM call rows on `cirislens.trace_llm_calls`.
    /// Used by cost / latency / model-breakdown dashboards and
    /// prompt-hash analysis. Cursor-paged; newest-first.
    ///
    /// `trace_llm_calls` carries no per-row cohort_scope; visibility is
    /// inherited from the parent trace, which lens-core gates at the
    /// trace layer. `scope` is accepted for surface uniformity and is a
    /// documented no-op here (v4.0).
    fn list_llm_calls(
        &self,
        filter: LlmCallFilter,
        cursor: Option<LlmCallCursor>,
        limit: i64,
        scope: CallerScope,
    ) -> impl Future<Output = Result<LlmCallListPage, Error>> + Send;

    /// Roll up LLM call costs by model, by agent, by deployment
    /// domain, plus window-level totals. Replaces the lens-side raw
    /// SQL cost-aggregation pass. `scope` no-op (see [`Self::list_llm_calls`]).
    fn aggregate_llm_costs(
        &self,
        filter: LlmCallFilter,
        scope: CallerScope,
    ) -> impl Future<Output = Result<LlmCostAggregate, Error>> + Send;

    // ── Repository statistics (#159, FSD §6.2) ─────────────────────

    /// Corpus-wide repository statistics over a window — the #159
    /// primitive that drives CIRISLens' `/repository/statistics`.
    ///
    /// One round-trip per call (Postgres single CTE §10.1; SQLite
    /// two-step §10.2) computing the full FSD shape: totals, DMA score
    /// distributions, conscience pass/override rates, action histogram,
    /// fragility breakdown, per-domain rollup. Scope-gated (§4.3) on the
    /// `trace_events.cohort_scope` / `cohort_target_id` columns and
    /// routed through the §7 substrate cache — the result carries
    /// `cache_hit` and `evaluated_at_unix_ms` ([`Aggregate`]). Every
    /// aggregate carries `sample_count` (AV-43; top-vs-nested per §6.3).
    ///
    /// Empty window → `sample_count: 0`, never an error (FSD §6.3,
    /// "zero is honest").
    fn get_repository_statistics(
        &self,
        filter: RepositoryFilter,
        scope: CallerScope,
    ) -> impl Future<Output = Result<RepositoryStatistics, Error>> + Send;

    // ── Section G — Corpus shape (CIRISPersist#23 §G) ──────────────

    /// Corpus-shape rollup for a window. Returns distinct-trace
    /// counts broken down by task_class, QA language / question num,
    /// agent name + template, primary model, deployment region.
    /// Drives `scripts/corpus_shape.py` and cohort dashboards.
    /// Scope-gated on `trace_events.cohort_scope` / `cohort_target_id`.
    fn corpus_shape(
        &self,
        filter: CorpusShapeFilter,
        scope: CallerScope,
    ) -> impl Future<Output = Result<CorpusShape, Error>> + Send;

    // ── Section H — Privacy / scrub observability (CIRISPersist#23 §H) ──

    /// Scrub-stats aggregate for a window. Drives privacy dashboards.
    /// `envelopes_scrubbed` + `by_trace_level` are populated from
    /// `cirislens.trace_events.pii_scrubbed`;
    /// `fields_scrubbed_total` + `by_entity_type` are gated on the
    /// v0.6.0 post-ingest classification pipeline (CIRISPersist#19).
    /// Scope-gated on `trace_events.cohort_scope` / `cohort_target_id`.
    fn aggregate_scrub_stats(
        &self,
        window: TimeWindow,
        scope: CallerScope,
    ) -> impl Future<Output = Result<ScrubAggregate, Error>> + Send;

    // ── Section I — Federation observability bulk (CIRISPersist#23 §I) ──

    /// Page through `cirislens.federation_keys`. Cursor-paged
    /// newest-first by `(valid_from DESC, key_id DESC)`. Filters
    /// compose AND-style; `revoked` and `pqc_completed` are SQL-side
    /// EXISTS predicates / `pqc_completed_at IS NULL` checks.
    ///
    /// `federation_keys` is the federation-tier directory — it carries
    /// no per-row cohort_scope/target. `scope` is accepted for surface
    /// uniformity and is a documented no-op in v4.0 (federation keys are
    /// federation-visible by construction).
    fn list_federation_keys(
        &self,
        filter: FederationKeyFilter,
        cursor: Option<FederationKeyCursor>,
        limit: i64,
        scope: CallerScope,
    ) -> impl Future<Output = Result<FederationKeyListPage, Error>> + Send;

    /// Page through `cirislens.federation_attestations`. Newest-first
    /// by `(asserted_at, attestation_id)`. Scope-gated (§4.3) on
    /// `federation_attestations.cohort_scope` / `attested_key_id`.
    fn list_attestations(
        &self,
        filter: AttestationFilter,
        cursor: Option<AttestationCursor>,
        limit: i64,
        scope: CallerScope,
    ) -> impl Future<Output = Result<AttestationListPage, Error>> + Send;

    /// List every attestation whose subject is `target` (i.e.
    /// `attested_key_id = target`), newest-first by
    /// `(asserted_at, attestation_id)`, cursor-paged. #135 + part of
    /// #150.
    ///
    /// The scope predicate gates on the attestation's OWN
    /// `cohort_scope` (§4.3), NOT the target's. `federation_attestations`
    /// carries `cohort_scope` but no per-row cohort *target* column
    /// (V056 added only `cohort_scope`; the target column an analogue
    /// of `trace_events.cohort_target_id` would be named
    /// `cohort_target_id` and is a documented follow-up — see
    /// `cohort_scope_sql_predicate`'s broad-tier branch). With no
    /// target column to resolve, the membership-gated tiers
    /// (self/family/community) cannot resolve a specific cohort target
    /// and are gated to the broad visibility tiers only.
    fn list_attestations_for(
        &self,
        target: &str,
        cursor: Option<AttestationCursor>,
        limit: i64,
        scope: CallerScope,
    ) -> impl Future<Output = Result<AttestationListPage, Error>> + Send;

    /// Page through `cirislens.federation_revocations`. Newest-first
    /// by `(revoked_at, revocation_id)`. Revocations are federation-tier
    /// transparency events; `scope` no-op in v4.0.
    fn list_revocations(
        &self,
        filter: RevocationFilter,
        cursor: Option<RevocationCursor>,
        limit: i64,
        scope: CallerScope,
    ) -> impl Future<Output = Result<RevocationListPage, Error>> + Send;

    // ── Section F — Coherence Ratchet inputs (CIRISPersist#23 §F) ──

    /// Cross-agent divergence z-scores within a deployment domain.
    /// Lens computes detection from these inputs; persist provides
    /// the windowed peer-mean reference. Scope-gated on
    /// `trace_events.cohort_scope` / `cohort_target_id`.
    fn cross_agent_divergence(
        &self,
        deployment_domain: &str,
        window: TimeWindow,
        metric: DeviationMetric,
        scope: CallerScope,
    ) -> impl Future<Output = Result<Vec<DivergenceRow>, Error>> + Send;

    /// Temporal drift between a baseline window and a comparison
    /// window for a single agent. Returns one row per metric.
    /// Scope-gated on `trace_events.cohort_scope` / `cohort_target_id`.
    fn temporal_drift(
        &self,
        agent_id_hash: &str,
        baseline: TimeWindow,
        comparison: TimeWindow,
        scope: CallerScope,
    ) -> impl Future<Output = Result<Vec<TemporalDriftRow>, Error>> + Send;

    /// Hash-chain gaps over a window — sequence-number discontinuities
    /// in the agent's audit_log timeline. Each gap is `(start, end)`.
    ///
    /// Reads the per-agent audit-log timeline keyed by `agent_id_hash`
    /// (AV-9 agent-ownership model), not the cohort-scoped
    /// `trace_events` content. `scope` is accepted for surface
    /// uniformity and is a documented no-op in v4.0.
    fn hash_chain_gaps(
        &self,
        agent_id_hash: &str,
        window: TimeWindow,
        scope: CallerScope,
    ) -> impl Future<Output = Result<Vec<HashChainGap>, Error>> + Send;

    /// Conscience-override rates per agent within a deployment domain,
    /// with the domain-average reference for ratio computation.
    /// Scope-gated on `trace_events.cohort_scope` / `cohort_target_id`.
    fn conscience_override_rates(
        &self,
        deployment_domain: &str,
        window: TimeWindow,
        scope: CallerScope,
    ) -> impl Future<Output = Result<Vec<OverrideRateRow>, Error>> + Send;

    // ── Section E — Scoring factor aggregates (CIRISPersist#23 §E) ─

    /// One bundled aggregate primitive returning everything any
    /// single CIRIS Capacity Score factor calculation needs in one
    /// DB round-trip. Composes the granular sub-primitives below.
    ///
    /// `baseline_window` is optional — when provided, the
    /// `drift_z_score` field is computed against the baseline; when
    /// absent, drift is `None`. Scope-gated on `trace_events`.
    fn aggregate_scoring_factors(
        &self,
        agent_id_hash: &str,
        window: TimeWindow,
        baseline_window: Option<TimeWindow>,
        scope: CallerScope,
    ) -> impl Future<Output = Result<ScoringFactorAggregate, Error>> + Send;

    /// Batch variant: fleet-wide score sweep in one round-trip.
    /// Returns one [`ScoringFactorAggregate`] per agent in input order.
    /// Threads the caller's `scope` through each per-agent aggregate.
    fn aggregate_scoring_factors_batch(
        &self,
        agent_id_hashes: &[String],
        window: TimeWindow,
        baseline_window: Option<TimeWindow>,
        scope: CallerScope,
    ) -> impl Future<Output = Result<Vec<ScoringFactorAggregate>, Error>> + Send;

    /// Streaming variant (CIRISPersist#197, substrate side of
    /// CIRISLensCore#44): invoke `callback` with each agent's
    /// [`ScoringFactorAggregate`] as it completes, so the lens can
    /// SSE/`StreamingResponse` per-agent rows instead of blocking on the
    /// whole fleet. Returns a terminal [`StreamSummary`] once the scan
    /// finishes.
    ///
    /// The callback returns `bool`: `false` aborts the scan (the future
    /// resolves with `aborted: true` and no further callbacks fire).
    /// Composed over the #196 rollup on Postgres+TimescaleDB (sub-second
    /// total). Shares the batch path's scoring-factors cache — a warm
    /// batch makes this a pure cache replay (`cache_hit: true`).
    fn aggregate_scoring_factors_stream(
        &self,
        agent_id_hashes: Vec<String>,
        window: TimeWindow,
        baseline_window: Option<TimeWindow>,
        scope: CallerScope,
        callback: impl FnMut(ScoringFactorAggregate) -> bool + Send + 'static,
    ) -> impl Future<Output = Result<StreamSummary, Error>> + Send;

    /// Granular: count traces matching a filter. Used by analysts
    /// composing narrower questions than the bundled aggregate.
    /// Scope-gated on `trace_events.cohort_scope` / `cohort_target_id`.
    fn count_traces(
        &self,
        filter: TraceFilter,
        scope: CallerScope,
    ) -> impl Future<Output = Result<i64, Error>> + Send;

    /// Granular: count conscience overrides matching a filter.
    /// Scope-gated on `trace_events`.
    fn count_overrides(
        &self,
        filter: TraceFilter,
        scope: CallerScope,
    ) -> impl Future<Output = Result<i64, Error>> + Send;

    /// Granular: count identity changes (agent_id_hash transitions
    /// per agent_name) matching a filter. Scope-gated on `trace_events`.
    fn count_identity_changes(
        &self,
        filter: TraceFilter,
        scope: CallerScope,
    ) -> impl Future<Output = Result<i64, Error>> + Send;

    /// Granular: audit-chain aggregate (total signed entries +
    /// detected gaps) for a filter window. Scope-gated on `trace_events`.
    fn aggregate_audit_chain(
        &self,
        filter: TraceFilter,
        scope: CallerScope,
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

    /// The cohort_scope admission gate (§4.3) refused the read. Carries
    /// a structured [`ScopeRefusalReason`](crate::scope::ScopeRefusalReason)
    /// so consumers can distinguish *why* — wrong identity vs no family
    /// membership vs no community membership vs boundary-auth failure are
    /// different conditions with different remediations (FSD §8.2).
    ///
    /// New in v4.0. Replaces the v3.x `NotImplemented` escape hatch as
    /// the trait's structured-failure direction: both backends implement
    /// every method, so "not implemented" is no longer an error state.
    #[error("scope refused: {0}")]
    ScopeRefused(#[from] crate::scope::ScopeRefusalReason),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    /// THREAT_MODEL.md AV-15: this is what crosses HTTP / PyO3
    /// boundaries; verbose `Display` form goes to tracing only.
    ///
    /// `read_scope_refused` is the single boundary-crossing token for a
    /// scope refusal; callers needing machine-distinguishable detail read
    /// [`ScopeRefusalReason::kind`](crate::scope::ScopeRefusalReason::kind)
    /// off the inner reason (FSD §8.2).
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "read_invalid_argument",
            Error::InvalidCursor(_) => "read_invalid_cursor",
            Error::Backend(_) => "read_backend",
            Error::ScopeRefused(_) => "read_scope_refused",
        }
    }
}
