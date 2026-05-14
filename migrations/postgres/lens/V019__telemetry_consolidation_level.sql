-- V019 — telemetry consolidation tier column (v1.0.0, CIRISAgent#756 Q7).
--
-- Adds the 4-tier (basic/daily/weekly/monthly) consolidation marker
-- to cirisgraph.nodes — TSDB summary rows already live here as
-- node_type='tsdb_summary' (V015 wrote them with summary JSON in
-- attributes). The column is a first-class TEXT field so the
-- "latest summary at level X for metric Y" query can use a real
-- index without parsing JSONB at scan time.
--
-- # Why a real column (not just JSON-extract)
--
-- Multi-tier rollup pattern (CIRISAgent's TSDBConsolidationService)
-- queries summaries by tier ALL the time on the rollup path: the
-- daily-tier rollup reads basic-tier summaries; weekly reads daily;
-- monthly reads weekly. Doing that via `attributes->>'consolidation_level'`
-- means every rollup pass is a full table scan filtered in memory.
-- Promoting to a column lets us index it composite with metric_name
-- and period_start.
--
-- # Why DEFAULT 'basic'
--
-- Pre-V019 summary rows were all basic-tier (the only tier that
-- existed). The default backfills them correctly without a separate
-- UPDATE. The CHECK constraint prevents typos at write time —
-- application-layer is the primary gate (the Rust enum), DB is
-- defense in depth.
--
-- # Non-tsdb_summary rows
--
-- Other node_type values (`agent`, `user`, `channel`, `config`,
-- `tsdb_data`, …) get DEFAULT 'basic' too — the column is only
-- meaningful for tsdb_summary, but we don't gate it via partial
-- column / generated column because that adds dialect complexity.
-- Consumers should always filter by `node_type = 'tsdb_summary'`
-- before trusting this column.

BEGIN;

ALTER TABLE cirisgraph.nodes
    ADD COLUMN IF NOT EXISTS consolidation_level TEXT NOT NULL DEFAULT 'basic'
        CHECK (consolidation_level IN ('basic', 'daily', 'weekly', 'monthly'));

-- "latest summary at level X for metric Y" index. The metric_name
-- and period_start live inside the attributes JSONB blob; we use an
-- expression index so the rollup queries — which filter by both
-- node_type='tsdb_summary' AND consolidation_level=$tier AND the
-- JSON-extracted metric_name — can hit a single index.
CREATE INDEX IF NOT EXISTS tsdb_summary_level_metric_period
    ON cirisgraph.nodes (
        node_type,
        consolidation_level,
        (attributes->>'metric_name'),
        ((attributes->>'period_start')::timestamptz) DESC
    )
    WHERE node_type = 'tsdb_summary';

COMMENT ON COLUMN cirisgraph.nodes.consolidation_level IS
    'v1.0.0 (CIRISAgent#756 Q7) — TSDB rollup tier for node_type=tsdb_summary rows: basic (6h, raw obs), daily (basic rollup), weekly (daily rollup), monthly (weekly rollup). DEFAULT basic; CHECK-gated for typo defense.';

COMMIT;
