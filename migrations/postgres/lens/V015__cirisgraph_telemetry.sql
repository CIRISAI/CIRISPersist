-- V015 — telemetry + TSDB consolidation (v0.8.2, CIRISPersist#36).
--
-- Absorbs the agent's TelemetryService + TSDBConsolidationService
-- write/read paths. Raw metrics are high-frequency, short-lived
-- (24h default TTL); 6-hour rollups land as `tsdb_summary` nodes in
-- cirisgraph.nodes (V013) with TEMPORAL_NEXT / TEMPORAL_PREV edges
-- between adjacent summaries.
--
-- # Why telemetry_metrics is a separate table (not graph nodes)
--
-- High-frequency writes (per-metric-observation; can be 100s/sec
-- under load) don't fit graph-node semantics (versioned, audited).
-- Raw metrics get a flat, fast-write table; the rollup pass moves
-- aggregated stats into cirisgraph.nodes where the typed graph
-- shape is useful. Tradeoff is one extra schema concept; gain is
-- that the cirisgraph.nodes write path stays cheap + auditable
-- without becoming a hot path for telemetry.
--
-- # Why per-period locks
--
-- Multi-instance deployments may run multiple consolidator workers.
-- The lock table coordinates so only one worker rolls up a given
-- (period_start, tenant_id) — caller acquires the lock,
-- consolidates, deletes raw rows, releases. Stale locks (>1h since
-- `locked_at`) auto-break on contended acquisition per AV-53.

BEGIN;

-- ── telemetry_metrics — raw observations ────────────────────────

CREATE TABLE IF NOT EXISTS cirisgraph.telemetry_metrics (
    metric_id         UUID PRIMARY KEY,
    metric_name       TEXT NOT NULL,

    -- Per-tenant isolation (same gate as cirisaudit AV-51).
    tenant_id         TEXT NOT NULL,

    -- The actual measurement.
    value             DOUBLE PRECISION NOT NULL,

    -- AV-52: free-form label set; size-capped at the trait surface
    -- (default 4 KiB JSONB; cardinality-capped per (tenant, name)
    -- on the runtime path).
    labels            JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Caller-asserted wall-clock. Indexed for time-window scans.
    observed_at       TIMESTAMPTZ NOT NULL,

    -- TTL — raw rows that pass this point are reapable by the
    -- consolidator's DELETE step. Default observed_at + 24h.
    expires_at        TIMESTAMPTZ NOT NULL,

    -- Audit envelope is intentionally OMITTED on raw metrics:
    -- (a) they're ephemeral (24h), (b) the rolled-up summary node
    -- in cirisgraph.nodes carries the audit envelope.
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Hot path: window scan per (tenant, metric_name).
CREATE INDEX IF NOT EXISTS telemetry_window
    ON cirisgraph.telemetry_metrics (tenant_id, metric_name, observed_at);

-- Reaping path: expired rows.
CREATE INDEX IF NOT EXISTS telemetry_expires
    ON cirisgraph.telemetry_metrics (expires_at);

COMMENT ON TABLE cirisgraph.telemetry_metrics IS
    'v0.8.2 (CIRISPersist#36) — raw telemetry observations (24h-lived). Rolled up every 6h into tsdb_summary nodes in cirisgraph.nodes; raw rows deleted after rollup. No per-row audit envelope (ephemeral); rolled-up summary carries the audit path.';

-- ── consolidation_locks — multi-instance coordination ──────────

CREATE TABLE IF NOT EXISTS cirisgraph.consolidation_locks (
    period_start      TIMESTAMPTZ NOT NULL,
    period_end        TIMESTAMPTZ NOT NULL,
    tenant_id         TEXT NOT NULL,
    locked_by         TEXT NOT NULL,
    locked_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (period_start, tenant_id),
    CHECK (period_end > period_start)
);

-- Used by AV-53 stale-lock detection on contended acquisition.
CREATE INDEX IF NOT EXISTS consolidation_locks_locked_at
    ON cirisgraph.consolidation_locks (locked_at);

COMMENT ON TABLE cirisgraph.consolidation_locks IS
    'v0.8.2 (CIRISPersist#36) — per-(period_start, tenant_id) lock for the TSDB rollup. Acquired via INSERT…ON CONFLICT DO NOTHING; stale locks (>1h since locked_at) auto-break per AV-53.';

COMMIT;
