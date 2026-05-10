# FSD: v0.5.0 — Federation Read Primitives (sections A/B/F/E)

**Status:** In flight (v0.5.0 implementation)
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.7
**Started:** 2026-05-10
**Tracks:** [CIRISPersist#23](https://github.com/CIRISAI/CIRISPersist/issues/23)
**Companion:** v0.5.1 will ship sections C/D/G/H/I after lens validates the v0.5.0 batch.

---

## 1. Scope (v0.5.0 batch)

This release ships four of the nine sections from CIRISPersist#23:

| § | Section | What | Drives |
|---|---|---|---|
| **A** | Trace listing | `TraceSummary` rows w/ denormalized DMA / conscience / action / cost | `/repository/traces`, dashboards, scoring corpus filters |
| **B** | Trace detail | Full `TraceDetail` w/ components + LLM calls + envelope refs | `/repository/traces/{trace_id}` |
| **F** | Coherence Ratchet inputs | `DivergenceRow`, `TemporalDriftRow`, `HashChainGap`, `OverrideRateRow` | `/coherence-ratchet/stats` (currently 500'ing) |
| **E** | Scoring factor aggregates | `ScoringFactorAggregate` + batch + granular sub-primitives | `api/scoring.py` raw-SQL replacement |

Deferred to v0.5.1:

| § | Section | Why deferred |
|---|---|---|
| C | Task-grouped listing | Wraps A; lens can group on the lens side as v0.5.0 workaround |
| D | LLM call surface | `trace_llm_calls` carve-out can be lens-internal until v0.5.1 |
| G | Corpus shape | Operator dashboards; not user-bleeding |
| H | Scrub stats | Privacy observability; not user-bleeding |
| I | Federation observability bulk | Monitoring dashboards; not user-bleeding |

## 2. Surface duality (v0.4.1 precedent)

Every primitive lands as **both**:

- **Rust-public free function** in `crate::read::*` (or method on `ReadEngine` trait)
- **PyO3 wrapper** on `Engine`

Single source of truth. No Python-only reimplementation drifting from Rust. Same shape `verify_hybrid_via_directory` established in v0.4.1.

## 3. Module shape

```
src/read/
├── mod.rs              — ReadEngine trait + Error + module docs
├── types.rs            — Common types: TraceCursor, TimeWindow, TraceFilter,
│                          DeviationMetric, TraceClass, etc.
├── trace.rs            — Section A + B: TraceSummary, TraceListPage,
│                          TraceDetail, payload-extraction logic
├── ratchet.rs          — Section F: DivergenceRow, TemporalDriftRow,
│                          HashChainGap, OverrideRateRow + queries
└── scoring.rs          — Section E: ScoringFactorAggregate + sub-aggregates
                          + granular count_* primitives
```

Backends implement `ReadEngine` per the existing `Backend` / `FederationDirectory` / `OutboundQueue` / `DerivedSchema` precedent:

- **Postgres** — full impl (production / lens-tier deployments)
- **Memory** — `NotImplemented` for SQL-heavy primitives; in-memory iteration for trivial ones
- **SQLite** — `NotImplemented` for the v0.5.0 batch; sovereign-mode v0.6.x track

## 4. Cursor pagination contract

All list primitives use opaque cursors built around `(ts, trace_id)` tuples. No `OFFSET/LIMIT`. Same pattern `fetch_trace_events_page` established in v0.2.0 (uses `(event_id)` for per-row cursoring).

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCursor {
    /// Ordering key — `started_at` of the last item on the previous page.
    pub last_ts: chrono::DateTime<chrono::Utc>,
    /// Tiebreaker — `trace_id` of the last item.
    pub last_trace_id: String,
}
```

Cursors are wire-stable; serialize to JSON as opaque strings on the PyO3 boundary so consumers don't depend on field shape.

## 5. AV-15 / AV-9 invariants

- **AV-15 (FFI sanitization)** — no attacker-controlled strings cross the boundary. Error kinds use closed-set `&'static str` tokens like the existing `IngestError::kind()` pattern.
- **AV-9 (cross-agent dedup)** — every trace-scoped read MUST gate on `agent_id_hash` consistently. A malicious peer cannot read another peer's traces via `trace_id` alone (the per-trace queries take `trace_id` AS the key, but the returned `TraceSummary` carries `agent_id_hash` so the caller can authorize at their layer).

## 6. New AV-43 (read-side adversary) — threat model addition

Added to `docs/THREAT_MODEL.md` in this release:

> **AV-43: Read-side adversary inference attack**
>
> *Attack*: A federation peer with read access uses the aggregate primitives (E/F/G/H) to infer per-trace content of another peer's traces by pattern analysis — e.g., correlating `cross_agent_divergence` outputs against narrowly-windowed `aggregate_scoring_factors` to deanonymize.
>
> *Mitigation v0.5.0*: aggregates return computed statistics, not per-trace content. The smallest-window primitive (`aggregate_scoring_factors`) requires a `TimeWindow` that admits standard statistical disclosure controls (caller's policy: minimum cell size, k-anonymity gates) BEFORE persist returns the aggregate. Persist's substrate doesn't itself enforce k-anonymity (that's policy); it returns counts truthfully and documents the window-size dependency.
>
> *Residual*: a federation operator with `cirislens_reader` role (or its v0.5.1 retirement target) running narrow windows can in principle reconstruct trace patterns. The aggregation primitives don't widen this surface — the underlying rows were already accessible to that role. v0.5.1's full retirement of the carve-out + AV-15-safe primitive layer removes the direct-SQL path entirely; the typed primitives are the only read surface.

The "primary read surface; v0.5.1 closes the carve-out" framing — fully retiring `cirislens_reader` requires section D (LLM call surface) which lands in v0.5.1.

## 7. Acceptance criteria for v0.5.0

1. Sections A + B + F + E all ship: Rust-public free function + PyO3 wrapper + typed structs.
2. Cursor pagination on all list primitives.
3. Continuous-aggregate backing on E where window granularity allows (hourly+).
4. Tests: round-trip per primitive; cursor stability; AV-15 / AV-9 invariant gates.
5. THREAT_MODEL.md updated with AV-43.
6. CHANGELOG documents v0.5.0 as the primary read surface; carve-out retirement deferred to v0.5.1.
7. `fetch_trace_events_page` docstring carve-out language softened: still recommended for ad-hoc analytical queries, BUT marked "deprecated for new lens code; use `list_trace_summaries` / `get_trace_detail`" pending v0.5.1.

## 8. Implementation order

1. **Foundation** — `src/read/{mod.rs, types.rs}` + `ReadEngine` trait + Error enum + Cursor + TimeWindow + TraceFilter + module wired into `lib.rs` + `prelude.rs`.
2. **Section A** — `src/read/trace.rs` (TraceSummary path) + Postgres impl + Memory NotImplemented + tests.
3. **Section B** — extends section A's module: `TraceDetail` + `get_trace_detail` + Postgres impl + tests.
4. **Section F** — `src/read/ratchet.rs` + Postgres impl + tests.
5. **Section E** — `src/read/scoring.rs` + Postgres impl (with continuous-aggregate backing where applicable) + batch primitive + granular sub-primitives + tests.
6. **PyO3 surface** — wraps every Rust function above; matches the rlib path in shape.
7. **Threat model** — AV-43 narrative + summary table row.
8. **CHANGELOG** — v0.5.0 entry documenting the surface + carve-out v0.5.1 deferral.
9. **Release** — Cargo.toml already at 0.5.0; commit + tag + push.

## 9. Out of scope for v0.5.0

- Sections C, D, G, H, I (deferred to v0.5.1 explicitly).
- Lens main migration off `SELECT FROM cirislens.*` — the persist primitives ship; lens-side surgery happens in lockstep but is a CIRISLens repo concern.
- Capacity Score formula composition (lens-domain logic; persist exposes inputs).
- Coherence Ratchet detection algorithms (lens-domain logic; persist exposes windowed inputs).
- Retiring `cirislens_reader` Postgres role (deferred to v0.5.1 with section D).
