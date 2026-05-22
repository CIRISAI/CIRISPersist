-- V042 — data-aware analytics indexes on trace_events (SQLite dialect).
-- Postgres parity: migrations/postgres/lens/V042 (same query shapes,
-- PG extraction syntax).
--
-- # The trick — "covering indexes as a poor-man's column store"
--
-- The ReadEngine analytics query set is FIXED (~21 methods) over
-- trace_events, an append-mostly time-series. The scored scalars
-- (csdma_plausibility_score, dsdma_domain_alignment, idma_k_eff,
-- idma_correlation_risk) each live in the JSON `payload` of exactly
-- ONE event_type (DMA_RESULTS / IDMA_RESULT). So an index that is:
--
--   * PARTIAL  — scoped `WHERE event_type = '<that type>'` → physically
--                holds only the ~1/3 of rows where the scalar is
--                meaningful (row elimination, like a column-store
--                segment skipping irrelevant rows).
--   * COMPOSITE — leads with the query's seek key (deployment_domain,
--                ts) so the equality + range predicate become index
--                seek bounds.
--   * COVERING — trails every other column the query reads
--                (agent_id_hash, agent_name) AND the EXPRESSION
--                `json_extract(payload, '$.<field>')` that materializes
--                the scalar. The planner then answers the whole query
--                from the index with no table B-tree (heap) fetch and
--                never re-parses the JSON.
--
-- # Why domain-led, ts second (NOT agent_id_hash second)
--
-- cross_agent_divergence filters `deployment_domain = ?1 AND ts >= ?2
-- AND ts < ?3` with NO agent_id_hash equality (it GROUPs BY it). For
-- the `ts` range to be a seek bound it must sit immediately after the
-- equality column — so the key is (deployment_domain, ts, ...). An
-- (deployment_domain, agent_id_hash, ts) shape would push ts to
-- position 3 and the range could not seek.
--
-- # Exact-expression-match constraint
--
-- SQLite's planner uses an expression index only when the index
-- expression is BYTE-IDENTICAL to the query's. `json_extract(payload,
-- '$.<field>')` here is copied verbatim from src/store/sqlite.rs
-- cross_agent_divergence. PG's V042 differs only because PG extraction
-- syntax differs (-> / ->>) — same design, dialect-translated.
--
-- # Scope honesty — what V042 does NOT make index-only
--
-- temporal_drift, conscience_override_rates and aggregate_scoring_factors
-- keep their V041 (agent_id_hash|deployment_domain, ts) index-range
-- seek but stay heap-touching: temporal_drift's seek key is agent-led
-- (a domain-led index can't serve it without a second copy); the
-- conscience/scoring per-trace CTEs put the `event_type` test INSIDE a
-- CASE expression (no event_type in their WHERE), so they scan ALL
-- event_types of a trace and a partial-on-one-event_type index cannot
-- cover them. Making those index-only needs a near-table-width fat
-- index — explicitly out of scope (no fat indexes, V041 seek is the
-- realistic ceiling for them). See V042's commit / report.
--
-- # Refinery: no explicit BEGIN/COMMIT (refinery wraps each migration).

-- ── Group A: cross_agent_divergence covering indexes ───────────────
--
-- cross_agent_divergence (non-override branch) builds, per metric:
--   SELECT agent_id_hash, MIN(agent_name) AS agent_name,
--          AVG(json_extract(payload, '$.<field>')) AS mean,
--          COUNT(*) AS sample_count
--   FROM trace_events
--   WHERE deployment_domain = ?1 AND ts >= ?2 AND ts < ?3
--         AND event_type = '<EVENT>'
--         AND json_extract(payload, '$.<field>') IS NOT NULL
--   GROUP BY agent_id_hash HAVING COUNT(*) > 0
--
-- One partial+covering index per concrete (field, event_type) pair.
-- (deployment_domain, ts) are the seek bounds; (agent_id_hash,
-- agent_name, json_extract(...)) are the trailing covering columns so
-- the scan is index-only. (A temp B-tree for the GROUP BY remains —
-- agent_id_hash is not the leading column — but the heap fetch and
-- JSON re-parse are eliminated.)
--
-- The partial predicate is `event_type = '<EVENT>' AND
-- json_extract(payload, '$.<field>') IS NOT NULL` — the EXACT residual
-- filter cross_agent_divergence applies. The `IS NOT NULL` half is
-- not just row-elimination: csdma and dsdma both partial-on
-- 'DMA_RESULTS', so without the per-field `IS NOT NULL` discriminator
-- the planner treats the two as interchangeable for the seek and may
-- pick the WRONG one (whose trailing scalar column does not match the
-- query → a heap fetch instead of a covering scan). The discriminating
-- predicate makes each index match exactly one metric's query.

-- csdma_plausibility_score — DMA_RESULTS
CREATE INDEX IF NOT EXISTS trace_events_an_csdma
    ON trace_events (
        deployment_domain,
        ts,
        agent_id_hash,
        agent_name,
        json_extract(payload, '$.csdma_plausibility_score')
    )
    WHERE event_type = 'DMA_RESULTS'
          AND json_extract(payload, '$.csdma_plausibility_score') IS NOT NULL;

-- dsdma_domain_alignment — DMA_RESULTS
CREATE INDEX IF NOT EXISTS trace_events_an_dsdma
    ON trace_events (
        deployment_domain,
        ts,
        agent_id_hash,
        agent_name,
        json_extract(payload, '$.dsdma_domain_alignment')
    )
    WHERE event_type = 'DMA_RESULTS'
          AND json_extract(payload, '$.dsdma_domain_alignment') IS NOT NULL;

-- idma_k_eff — IDMA_RESULT
CREATE INDEX IF NOT EXISTS trace_events_an_idma_keff
    ON trace_events (
        deployment_domain,
        ts,
        agent_id_hash,
        agent_name,
        json_extract(payload, '$.idma_k_eff')
    )
    WHERE event_type = 'IDMA_RESULT'
          AND json_extract(payload, '$.idma_k_eff') IS NOT NULL;

-- idma_correlation_risk — IDMA_RESULT
CREATE INDEX IF NOT EXISTS trace_events_an_idma_corr
    ON trace_events (
        deployment_domain,
        ts,
        agent_id_hash,
        agent_name,
        json_extract(payload, '$.idma_correlation_risk')
    )
    WHERE event_type = 'IDMA_RESULT'
          AND json_extract(payload, '$.idma_correlation_risk') IS NOT NULL;

-- ── Group B: list_trace_summaries cheap-column covering index ──────
--
-- list_trace_summaries does GROUP BY trace_id with FILTER aggregates
-- over many payload fields — genuinely NOT index-only-able without a
-- fat per-field index (rejected: it would ~double storage and still
-- not cover the multi-field FILTER set). This (trace_id, ts) covering
-- index carries the cheap scalar columns the summary needs so the
-- GROUP-BY can run as an index-ordered grouping without sorting the
-- whole table; the payload-derived FILTER columns still require a row
-- fetch. Honest scope: this removes the sort, not the heap reads.
CREATE INDEX IF NOT EXISTS trace_events_an_trace_summary
    ON trace_events (trace_id, ts, event_type, agent_id_hash, cost_usd);
