# FSD: Federation Read Primitives (CIRISPersist#23, sections A–I)

**Status:** Implemented. The primitives are methods on the `ReadEngine` trait in `src/ceg/` (`crate::read` re-exports them), implemented by both `PostgresBackend` and `SqliteBackend` and wrapped on the Python `Engine`. The data access surface that scopes them is `FSD/V4_0_DATA_ACCESS_SURFACE.md`.
**Tracks:** [CIRISPersist#23](https://github.com/CIRISAI/CIRISPersist/issues/23)

---

## 1. Scope

The nine sections of CIRISPersist#23:

| § | Section | Primitives | Drives |
|---|---|---|---|
| **A** | Trace listing | `list_trace_summaries`, `get_trace_summary` — `TraceSummary` rows with denormalized DMA / conscience / action / cost | `/repository/traces`, dashboards, scoring corpus filters |
| **B** | Trace detail | `get_trace_detail` — full `TraceDetail` with components, LLM calls, envelope refs | `/repository/traces/{trace_id}` |
| **C** | Task-grouped listing | `list_tasks` | task views |
| **D** | LLM call surface | `list_llm_calls`, `aggregate_llm_costs` | cost and model dashboards |
| **E** | Scoring factor aggregates | `aggregate_scoring_factors`, `aggregate_scoring_factors_batch`, `aggregate_scoring_factors_stream`, and granular `count_traces` / `count_overrides` / `count_identity_changes` | the lens scoring path |
| **F** | Coherence Ratchet inputs | `cross_agent_divergence`, `temporal_drift`, `hash_chain_gaps`, `conscience_override_rates` | `/coherence-ratchet/*` |
| **G** | Corpus shape | `corpus_shape`, `get_repository_statistics` | operator dashboards |
| **H** | Scrub stats | `aggregate_scrub_stats` | privacy observability |
| **I** | Federation observability bulk | `list_federation_keys`, `list_attestations`, `list_attestations_for`, `list_revocations` | monitoring dashboards |

`aggregate_audit_chain` sits beside them on the same trait.

## 2. Surface duality

Every primitive exists as **both**:

- a **Rust method** on `ReadEngine` (`crate::ceg`, re-exported through `crate::read` and the prelude), and
- a **PyO3 wrapper** on `Engine`.

Single source of truth: no Python-only reimplementation drifting from Rust. Three consumer tiers use the same surface — the lens API (Python), CIRISLensCore (Rust rlib), and sovereign-mode agents reading their own data.

## 3. Module shape

The trait is declared in `src/ceg/mod.rs`; its types and per-topic code live under `src/ceg/` (`types/`, `list/`, `aggregates/`, `streaming/`, …). Both backends implement it in full (`impl ReadEngine for PostgresBackend` / `for SqliteBackend`); no primitive returns `NotImplemented`. Every method takes a trailing `CallerScope` (`FSD/V4_0_DATA_ACCESS_SURFACE.md` §8.1), and every trace-scoped read is gated on `trace_events.cohort_scope` / `cohort_target_id`.

Scoring aggregates (§E) read from a plain rollup table on both backends (V081); there is no TimescaleDB dependency.

## 4. Cursor pagination contract

All list primitives use opaque cursors built around `(ts, trace_id)` tuples. No `OFFSET/LIMIT`. Same pattern as `Backend::fetch_trace_events_page` (which cursors per row on `event_id`).

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCursor {
    /// Ordering key — `started_at` of the last item on the previous page.
    pub last_ts: chrono::DateTime<chrono::Utc>,
    /// Tiebreaker — `trace_id` of the last item.
    pub last_trace_id: String,
}
```

Cursors are wire-stable and serialize to JSON as opaque strings on the PyO3 boundary, so consumers do not depend on the field shape.

## 5. AV-15 / AV-9 invariants

- **AV-15 (FFI sanitization)** — no attacker-controlled strings cross the boundary. Error kinds are closed-set `&'static str` tokens, like `IngestError::kind()`.
- **AV-9 (cross-agent dedup)** — every trace-scoped read carries `agent_id_hash`, so the caller can authorize per-trace access at its layer. The per-trace queries take `trace_id` as the key; the returned `TraceSummary` names the agent.

## 6. AV-43 — read-side adversary

`docs/THREAT_MODEL.md` AV-43:

> *Attack*: A federation peer with read access uses the aggregate primitives (E/F/G/H) to infer per-trace content of another peer's traces by pattern analysis — e.g., correlating `cross_agent_divergence` outputs against narrowly-windowed `aggregate_scoring_factors` to deanonymize.
>
> *Mitigation*: aggregates return computed statistics, not per-trace content, and surface `sample_count` / `trace_count` explicitly so callers can apply statistical disclosure controls (minimum cell size, k-anonymity) at their layer. Persist does not enforce k-anonymity itself (that is policy); it returns counts truthfully and documents the window-size dependency.
>
> *Residual*: a party with direct SQL read access (the `cirislens_reader` role, V005) running narrow windows can in principle reconstruct trace patterns. The aggregation primitives do not widen that surface — the underlying rows are already accessible to that role.

## 7. Acceptance criteria

1. Every section A–I exists as a Rust method and a PyO3 wrapper, with typed structs.
2. Cursor pagination on all list primitives.
3. Tests: round-trip per primitive; cursor stability; AV-15 / AV-9 invariant gates; both backends.
4. `docs/THREAT_MODEL.md` carries AV-43.

## 8. Out of scope

- Capacity Score formula composition (lens-domain logic; persist exposes the inputs).
- Coherence Ratchet detection algorithms (lens-domain logic; persist exposes windowed inputs).
- The lens's own migration off direct `SELECT FROM cirislens.*` queries (a CIRISLens concern).
