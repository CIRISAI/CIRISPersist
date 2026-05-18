-- V026 — service correlations substrate, SQLite dialect (v1.5.11,
-- CIRISPersist#59 #3).
--
-- Postgres parity (postgres/lens/V026). Dialect translations:
--
--   TIMESTAMPTZ              → TEXT (RFC 3339)
--   JSONB                    → TEXT (raw JSON string)
--   NOW()                    → CURRENT_TIMESTAMP
--   REAL                     → REAL (matches the agent's existing
--                              `ciris_engine.db.service_correlations`
--                              REAL declaration; SQLite preserves
--                              the float type affinity)
--
-- Dual-purpose schema (service-interaction + TSDB metric + trace
-- span + log) is one table with `correlation_type` as the
-- discriminator. See the PG migration for the design rationale.
--
-- No FK on parent_span_id — distributed-trace spans cross service
-- boundaries and the parent span may live elsewhere; tree assembly
-- is a JOIN at read time. Same trade-off as on PG.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here.

CREATE TABLE cirislens_service_correlations (
    correlation_id        TEXT PRIMARY KEY,
    service_type          TEXT NOT NULL,
    handler_name          TEXT NOT NULL,
    action_type           TEXT NOT NULL,
    request_data          TEXT,
    response_data         TEXT,
    status                TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'completed',
                          'failed', 'cancelled')),
    created_at            TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    correlation_type      TEXT NOT NULL DEFAULT 'service_interaction'
        CHECK (correlation_type IN ('service_interaction', 'metric',
                                    'trace', 'log')),
    timestamp             TEXT,
    metric_name           TEXT,
    metric_value          REAL,
    log_level             TEXT,
    trace_id              TEXT,
    span_id               TEXT,
    parent_span_id        TEXT,
    tags                  TEXT,
    retention_policy      TEXT NOT NULL DEFAULT 'raw'
        CHECK (retention_policy IN ('raw', 'aggregated', 'summary',
                                    'retained_indefinitely')),
    agent_occurrence_id   TEXT NOT NULL DEFAULT 'default'
);

-- Hot path #1: list-by-service. service-interaction recency listing
-- scoped to one occurrence + one service_type.
CREATE INDEX service_correlations_service_recency
    ON cirislens_service_correlations
    (agent_occurrence_id, service_type, updated_at DESC);

-- Hot path #2: metric/trace time-window scans.
CREATE INDEX service_correlations_type_time
    ON cirislens_service_correlations
    (correlation_type, timestamp DESC);

-- Hot path #3: distributed-trace assembly. Partial index.
CREATE INDEX service_correlations_trace_id
    ON cirislens_service_correlations (trace_id)
    WHERE trace_id IS NOT NULL;

-- Hot path #4: span tree walks. Partial index.
CREATE INDEX service_correlations_parent_span
    ON cirislens_service_correlations (parent_span_id)
    WHERE parent_span_id IS NOT NULL;

-- Hot path #5: TSDB-style metric_name + window scan. Partial index.
CREATE INDEX service_correlations_metric_time
    ON cirislens_service_correlations (metric_name, timestamp DESC)
    WHERE metric_name IS NOT NULL;
