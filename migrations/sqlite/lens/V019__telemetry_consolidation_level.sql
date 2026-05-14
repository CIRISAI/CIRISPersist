-- V019 — telemetry consolidation tier column, SQLite dialect.
--
-- Postgres parity (postgres/lens/V019): same column shape +
-- expression-indexed query path.
--
-- Dialect notes:
--   * SQLite's `ALTER TABLE ADD COLUMN` accepts NOT NULL + DEFAULT
--     but NOT a CHECK constraint (the CHECK is allowed at CREATE
--     TABLE time only). The CHECK is therefore enforced at the
--     application layer via the `ConsolidationLevel` Rust enum.
--     Documented convention: any direct SQL writer must round-trip
--     through the enum's wire-shape tokens.
--   * SQLite's expression index requires deterministic functions.
--     `json_extract` is deterministic; we use it directly in the
--     index expression to mirror the PG (attributes->>'…') form.

ALTER TABLE cirisgraph_nodes
    ADD COLUMN consolidation_level TEXT NOT NULL DEFAULT 'basic';

CREATE INDEX IF NOT EXISTS tsdb_summary_level_metric_period
    ON cirisgraph_nodes (
        node_type,
        consolidation_level,
        json_extract(attributes, '$.metric_name'),
        json_extract(attributes, '$.period_start')
    )
    WHERE node_type = 'tsdb_summary';
