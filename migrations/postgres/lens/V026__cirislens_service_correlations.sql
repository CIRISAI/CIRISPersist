-- V026 — service correlations substrate (v1.5.11, CIRISPersist#59 #3).
--
-- Third of 11 substrate absorptions ending CIRISAgent's direct
-- libsqlite access to `ciris_engine.db`. Mirrors CIRISAgent 2.8.13
-- `service_correlations` table with PG-dialect translations:
--
--   TEXT timestamp columns   → TIMESTAMPTZ
--   JSON-string columns      → JSONB (request_data / response_data /
--                              tags)
--   REAL                     → REAL (no PG-special handling — metric_value
--                              is a 4-byte float matching the agent's
--                              REAL declaration in SQLite)
--
-- Dual-purpose schema. The agent uses a single table for FOUR sub-
-- shapes — service-interaction tracking, TSDB metric points, OTLP-
-- style distributed-trace spans, and structured logs — discriminated
-- by the `correlation_type` column. We track that as one substrate
-- (and one trait surface) until access patterns force a split. The
-- five indexes below are the four hot-path read shapes.
--
-- Status vocabulary (`pending | active | completed | failed |
-- cancelled`) — service-interaction state-machine. Differs from the
-- tasks/thoughts vocabulary (`processing`/`deferred`); these are the
-- five values the agent's RPC layer asserts and matches the
-- `service_correlations.status` CHECK in `ciris_engine.db`.
--
-- correlation_type vocabulary (`service_interaction | metric | trace
-- | log`) — the FOUR sub-shapes the table multiplexes. The other
-- columns (metric_name/value, trace_id/span_id/parent_span_id,
-- log_level) are only meaningful for their owning correlation_type.
--
-- retention_policy vocabulary (`raw | aggregated | summary |
-- retained_indefinitely`) — TSDB consolidation policy. Per-row tag
-- so a downstream consolidator can scan `metric` rows by policy and
-- aggregate the `raw` ones into `aggregated` / `summary`.
--
-- No FK on parent_span_id — distributed-trace spans cross
-- service/process boundaries and the parent span may live in
-- another substrate's traces, in another agent's `ciris_engine.db`,
-- or be a synthetic span. The index treats parent_span_id as a
-- string pointer; tree assembly is a JOIN at read time, not an FK
-- constraint at write time.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens.service_correlations (
    correlation_id        TEXT PRIMARY KEY,
    service_type          TEXT NOT NULL,
    handler_name          TEXT NOT NULL,
    action_type           TEXT NOT NULL,
    request_data          JSONB,
    response_data         JSONB,
    status                TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'completed',
                          'failed', 'cancelled')),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    correlation_type      TEXT NOT NULL DEFAULT 'service_interaction'
        CHECK (correlation_type IN ('service_interaction', 'metric',
                                    'trace', 'log')),
    timestamp             TIMESTAMPTZ,
    metric_name           TEXT,
    metric_value          REAL,
    log_level             TEXT,
    trace_id              TEXT,
    span_id               TEXT,
    parent_span_id        TEXT,
    tags                  JSONB,
    retention_policy      TEXT NOT NULL DEFAULT 'raw'
        CHECK (retention_policy IN ('raw', 'aggregated', 'summary',
                                    'retained_indefinitely')),
    agent_occurrence_id   TEXT NOT NULL DEFAULT 'default'
);

-- Hot path #1: list-by-service. Service-interaction recency listing
-- scoped to one occurrence + one service_type.
CREATE INDEX service_correlations_service_recency
    ON cirislens.service_correlations
    (agent_occurrence_id, service_type, updated_at DESC);

-- Hot path #2: metric/trace time-window scans. `correlation_type`
-- discriminator + `timestamp` (event time) for TSDB-style window
-- queries.
CREATE INDEX service_correlations_type_time
    ON cirislens.service_correlations
    (correlation_type, timestamp DESC);

-- Hot path #3: distributed-trace assembly. Index only carries rows
-- that have a trace_id (every metric/log row will not).
CREATE INDEX service_correlations_trace_id
    ON cirislens.service_correlations (trace_id)
    WHERE trace_id IS NOT NULL;

-- Hot path #4: span tree walks. Reverse-lookup parent → children.
CREATE INDEX service_correlations_parent_span
    ON cirislens.service_correlations (parent_span_id)
    WHERE parent_span_id IS NOT NULL;

-- Hot path #5: TSDB-style metric_name + window scan. Partial index
-- carries only rows with a metric_name so non-metric correlations
-- don't bloat the index.
CREATE INDEX service_correlations_metric_time
    ON cirislens.service_correlations (metric_name, timestamp DESC)
    WHERE metric_name IS NOT NULL;

COMMENT ON TABLE cirislens.service_correlations IS
    'v1.5.11 (CIRISPersist#59 #3) — service correlations substrate. Absorbs CIRISAgent ciris_engine.db.service_correlations. Dual-purpose: service-interaction tracking + TSDB metrics + distributed-trace spans + logs. correlation_type column discriminates between sub-shapes.';
