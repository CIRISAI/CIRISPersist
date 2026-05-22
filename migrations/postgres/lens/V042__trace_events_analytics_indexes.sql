-- V042 — data-aware analytics indexes on trace_events (Postgres).
-- SQLite parity: migrations/sqlite/lens/V042 (same query shapes,
-- SQLite extraction syntax).
--
-- # The trick — "covering indexes as a poor-man's column store"
--
-- The ReadEngine analytics query set is FIXED (~21 methods) over
-- cirislens.trace_events, an append-mostly time-series. The scored
-- scalars (csdma_plausibility_score, dsdma_domain_alignment,
-- idma_k_eff, idma_correlation_risk) each live in the JSONB `payload`
-- of exactly ONE event_type (DMA_RESULTS / IDMA_RESULT). So an index
-- that is:
--
--   * PARTIAL  — scoped `WHERE event_type = '<that type>' AND
--                payload ? '<field>'` → physically holds only the
--                rows the query actually wants (row elimination — a
--                column-store segment skipping irrelevant rows).
--   * COMPOSITE — keyed leading (deployment_domain, ts) so the
--                equality + `ts` range predicate become index seek
--                bounds.
--   * COVERING — every other column the query reads
--                (agent_id_hash, agent_name) AND the EXPRESSION
--                `(payload->>'<field>')::float8` that materializes
--                the scalar are trailing KEY columns, so the planner
--                runs an Index Only Scan: no heap fetch, no JSONB
--                re-parse.
--
-- # Why domain-led, ts second (NOT agent_id_hash second)
--
-- cross_agent_divergence filters `deployment_domain = $1 AND ts >= $2
-- AND ts < $3` with NO agent_id_hash equality (it GROUPs BY it). For
-- the `ts` range to be a seek bound it must sit immediately after the
-- equality column — so the key LEADS with (deployment_domain, ts).
-- agent_id_hash, agent_name and the scalar follow as trailing key
-- columns (projection-only — read during the scan, never seeked).
--
-- # Trailing KEY columns, not INCLUDE — and never the raw payload
--
-- The scalar is carried as `(payload->>'<field>')::float8` — the
-- *extracted scalar*, an 8-byte float in the leaf — NOT the raw
-- `payload` JSONB blob (covering `payload` would ~double the index
-- size; explicitly avoided). It is a trailing **key** column, not an
-- `INCLUDE` column: Postgres `INCLUDE` accepts only plain table
-- columns, never expressions — so an expression that must be covered
-- has to live in the key. `(payload->>'<field>')::float8` is
-- immutable, hence valid as an index key expression. (Group B below,
-- which covers only plain columns, does use `INCLUDE`.)
--
-- # Exact-expression-match constraint
--
-- Postgres's planner uses an expression index only when the index
-- expression matches the query's. `(payload->>'<field>')::float8`
-- here is copied verbatim from src/store/postgres.rs
-- cross_agent_divergence (the AVG argument). SQLite's V042 differs
-- only because SQLite extraction syntax differs (json_extract) —
-- same design, dialect-translated.
--
-- # Scope honesty — what V042 does NOT make index-only
--
-- temporal_drift, conscience_override_rates and aggregate_scoring_factors
-- keep their V041 (agent_id_hash|deployment_domain, ts) index-range
-- seek but stay heap-touching: temporal_drift's seek key is agent-led
-- (a domain-led index can't serve it without a second copy); the
-- conscience/scoring per-trace CTEs put the `event_type` test INSIDE a
-- CASE/BOOL_OR expression (no event_type in their WHERE), so they scan
-- ALL event_types of a trace and a partial-on-one-event_type index
-- cannot cover them. Making those index-only needs a near-table-width
-- fat index — explicitly out of scope (V041 seek is the realistic
-- ceiling for them). See V042's commit / report.
--
-- # Refinery: no explicit BEGIN/COMMIT (refinery wraps each migration;
-- so plain CREATE INDEX, not CREATE INDEX CONCURRENTLY).

-- ── Group A: cross_agent_divergence covering indexes ───────────────
--
-- cross_agent_divergence (non-override branch) builds, per metric:
--   SELECT agent_id_hash, MIN(agent_name) AS agent_name,
--          AVG((payload->>'<field>')::float8) AS mean,
--          COUNT(*) FILTER (WHERE payload ? '<field>') AS sample_count
--   FROM cirislens.trace_events
--   WHERE deployment_domain = $1 AND ts >= $2 AND ts < $3
--         AND event_type = '<EVENT>'
--         AND payload ? '<field>'
--   GROUP BY agent_id_hash HAVING COUNT(*) > 0
--
-- One partial+covering index per concrete (field, event_type) pair.
-- Partial on BOTH `event_type = '<EVENT>'` AND `payload ? '<field>'`
-- — the exact residual filter the query applies, so the index holds
-- only rows the query wants. Key leads with (deployment_domain, ts)
-- for the seek, then carries (agent_id_hash, agent_name, extracted
-- scalar) as trailing key columns so the whole scan is Index Only.

-- csdma_plausibility_score — DMA_RESULTS
CREATE INDEX IF NOT EXISTS trace_events_an_csdma
    ON cirislens.trace_events
       (deployment_domain, ts, agent_id_hash, agent_name,
        ((payload->>'csdma_plausibility_score')::float8))
    WHERE event_type = 'DMA_RESULTS' AND payload ? 'csdma_plausibility_score';

-- dsdma_domain_alignment — DMA_RESULTS
CREATE INDEX IF NOT EXISTS trace_events_an_dsdma
    ON cirislens.trace_events
       (deployment_domain, ts, agent_id_hash, agent_name,
        ((payload->>'dsdma_domain_alignment')::float8))
    WHERE event_type = 'DMA_RESULTS' AND payload ? 'dsdma_domain_alignment';

-- idma_k_eff — IDMA_RESULT
CREATE INDEX IF NOT EXISTS trace_events_an_idma_keff
    ON cirislens.trace_events
       (deployment_domain, ts, agent_id_hash, agent_name,
        ((payload->>'idma_k_eff')::float8))
    WHERE event_type = 'IDMA_RESULT' AND payload ? 'idma_k_eff';

-- idma_correlation_risk — IDMA_RESULT
CREATE INDEX IF NOT EXISTS trace_events_an_idma_corr
    ON cirislens.trace_events
       (deployment_domain, ts, agent_id_hash, agent_name,
        ((payload->>'idma_correlation_risk')::float8))
    WHERE event_type = 'IDMA_RESULT' AND payload ? 'idma_correlation_risk';

-- ── Group B: list_trace_summaries cheap-column covering index ──────
--
-- list_trace_summaries does GROUP BY trace_id with FILTER aggregates
-- over many payload fields — genuinely NOT index-only-able without a
-- fat per-field index (rejected: ~doubles storage, still misses the
-- multi-field FILTER set). This (trace_id, ts) covering index
-- INCLUDEs the cheap scalar columns the summary needs so the GROUP-BY
-- runs as an index-ordered grouping without a full-table sort; the
-- payload-derived FILTER columns still require a heap fetch. Honest
-- scope: removes the sort, not the heap reads.
CREATE INDEX IF NOT EXISTS trace_events_an_trace_summary
    ON cirislens.trace_events (trace_id, ts)
    INCLUDE (event_type, agent_id_hash, cost_usd);
