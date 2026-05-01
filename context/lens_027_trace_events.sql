-- 027_trace_events.sql
-- Cut over from per-thought row collapse (accord_traces) to event-log
-- persistence per agent FSD/TRACE_EVENT_LOG_PERSISTENCE.md §5.
--
-- One row per `@streaming_step` broadcast. Append-only. attempt_index
-- replaces timestamp-ordering for repeated step points.
--
-- accord_traces is kept readable for pre-cutover history but no longer
-- written to. Read-path migration (view shim, dashboards) is a follow-up.

-- ─── trace_events: one row per ReasoningEvent broadcast ────────────────

CREATE TABLE IF NOT EXISTS cirislens.trace_events (
    event_id        BIGSERIAL,
    trace_id        TEXT        NOT NULL,
    thought_id      TEXT        NOT NULL,
    task_id         TEXT,
    step_point      TEXT,                                    -- gather_context | perform_dmas | …
    event_type      TEXT        NOT NULL,                    -- ReasoningEvent.value
    attempt_index   INT         NOT NULL DEFAULT 0,          -- monotonic per (thought_id, event_type)
    ts              TIMESTAMPTZ NOT NULL,
    agent_name      TEXT,
    agent_id_hash   TEXT,
    cognitive_state TEXT,
    trace_level     TEXT        NOT NULL,
    payload         JSONB       NOT NULL,                    -- the component.data dict
    -- denormalized cost columns for fast aggregation
    cost_llm_calls  INT,
    cost_tokens     INT,
    cost_usd        NUMERIC(10,6),
    -- batch-level provenance
    signature       TEXT,                                    -- per-trace agent signature
    signing_key_id  TEXT,
    signature_verified BOOLEAN   NOT NULL DEFAULT FALSE,
    schema_version  TEXT,                                    -- e.g. "2.7.0"
    pii_scrubbed    BOOLEAN     NOT NULL DEFAULT FALSE,
    PRIMARY KEY (event_id, ts)
);

CREATE INDEX IF NOT EXISTS trace_events_lookup
    ON cirislens.trace_events (trace_id, thought_id, event_type, attempt_index);
CREATE INDEX IF NOT EXISTS trace_events_journey
    ON cirislens.trace_events (thought_id, ts);
CREATE INDEX IF NOT EXISTS trace_events_agent_ts
    ON cirislens.trace_events (agent_name, ts DESC);
CREATE INDEX IF NOT EXISTS trace_events_type_ts
    ON cirislens.trace_events (event_type, ts DESC);

-- TimescaleDB hypertable for compression + retention parity with accord_traces
SELECT create_hypertable(
    'cirislens.trace_events', 'ts',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- ─── trace_llm_calls: per-LLM-call rows linked to parent event ─────────

CREATE TABLE IF NOT EXISTS cirislens.trace_llm_calls (
    call_id              BIGSERIAL,
    trace_id             TEXT        NOT NULL,
    thought_id           TEXT        NOT NULL,
    task_id              TEXT,
    parent_event_id      BIGINT,                              -- FK to trace_events.event_id (loose; hypertable)
    parent_event_type    TEXT,
    parent_attempt_index INT,
    attempt_index        INT         NOT NULL DEFAULT 0,
    ts                   TIMESTAMPTZ NOT NULL,
    duration_ms          INT,
    handler_name         TEXT,
    service_name         TEXT,
    model                TEXT,
    base_url             TEXT,
    response_model       TEXT,
    prompt_tokens        INT,
    completion_tokens    INT,
    prompt_bytes         INT,
    completion_bytes     INT,
    cost_usd             NUMERIC(10,6),
    status               TEXT,                                 -- ok | timeout | rate_limited | …
    error_class          TEXT,
    attempt_count        INT,                                  -- instructor retry counter
    retry_count          INT,                                  -- LLMBus-level retry counter
    prompt_hash          TEXT,
    prompt               TEXT,                                 -- only at trace_level=full_traces
    response_text        TEXT,                                 -- only at trace_level=full_traces
    payload              JSONB,
    PRIMARY KEY (call_id, ts)
);

CREATE INDEX IF NOT EXISTS trace_llm_calls_thought
    ON cirislens.trace_llm_calls (thought_id, ts);
CREATE INDEX IF NOT EXISTS trace_llm_calls_parent
    ON cirislens.trace_llm_calls (parent_event_id);
CREATE INDEX IF NOT EXISTS trace_llm_calls_model_ts
    ON cirislens.trace_llm_calls (model, ts DESC);
CREATE INDEX IF NOT EXISTS trace_llm_calls_status_ts
    ON cirislens.trace_llm_calls (status, ts DESC) WHERE status IS DISTINCT FROM 'ok';

SELECT create_hypertable(
    'cirislens.trace_llm_calls', 'ts',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- ─── retention + compression policies ─────────────────────────────────
-- Match accord_traces: compress after 7d, drop after 30d for trace_events.
-- llm_calls have higher cardinality, drop earlier.

SELECT add_compression_policy('cirislens.trace_events',  INTERVAL '7 days',  if_not_exists => TRUE);
SELECT add_retention_policy('cirislens.trace_events',    INTERVAL '30 days', if_not_exists => TRUE);
SELECT add_compression_policy('cirislens.trace_llm_calls', INTERVAL '3 days', if_not_exists => TRUE);
SELECT add_retention_policy('cirislens.trace_llm_calls',   INTERVAL '14 days', if_not_exists => TRUE);

-- ─── note on accord_traces ────────────────────────────────────────────
-- accord_traces is DEPRECATED FOR WRITES from this migration onward.
-- Reads still work against pre-cutover history. The trace handler in
-- api/accord_api.py was updated in the same change to write trace_events
-- instead. The view shim that exposes the new event-log shape under the
-- old per-thought-row API is a separate follow-up migration.
