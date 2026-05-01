-- 001 — trace_events + trace_llm_calls (carry over from
-- ~/CIRISLens/sql/027_trace_events.sql; renumbered to 001 as the
-- crate-owned baseline per FSD §3.1).
--
-- One row per `@streaming_step` broadcast (FSD §3.3 step 4 +
-- agent FSD/TRACE_EVENT_LOG_PERSISTENCE.md §5). Append-only.
-- Idempotency on `(trace_id, thought_id, event_type, attempt_index)`
-- per FSD §3.4 robustness primitive #4.

CREATE SCHEMA IF NOT EXISTS cirislens;

-- ─── trace_events: one row per ReasoningEvent broadcast ────────────

CREATE TABLE IF NOT EXISTS cirislens.trace_events (
    event_id        BIGSERIAL,
    trace_id        TEXT        NOT NULL,
    thought_id      TEXT        NOT NULL,
    task_id         TEXT,
    step_point      TEXT,
    event_type      TEXT        NOT NULL,
    attempt_index   INT         NOT NULL DEFAULT 0,
    ts              TIMESTAMPTZ NOT NULL,
    agent_name      TEXT,
    agent_id_hash   TEXT,
    cognitive_state TEXT,
    trace_level     TEXT        NOT NULL,
    payload         JSONB       NOT NULL,
    cost_llm_calls  INT,
    cost_tokens     INT,
    -- f64-shaped column. Was NUMERIC(10,6) in the lens-side
    -- 027_trace_events.sql; we use DOUBLE PRECISION so the Rust
    -- writer can pass `Option<f64>` directly without pulling
    -- rust_decimal into the dep tree. f64's ~15-17 sig digits is
    -- ample headroom for USD costs that are already approximate
    -- (LLM provider invoices round to fractional cents anyway).
    cost_usd        DOUBLE PRECISION,
    signature       TEXT,
    signing_key_id  TEXT,
    signature_verified BOOLEAN  NOT NULL DEFAULT FALSE,
    schema_version  TEXT,
    pii_scrubbed    BOOLEAN     NOT NULL DEFAULT FALSE,
    PRIMARY KEY (event_id, ts)
);

-- The dedup index FSD §3.4 #4 names. UNIQUE so ON CONFLICT DO NOTHING
-- can target it in INSERT ... ON CONFLICT.
CREATE UNIQUE INDEX IF NOT EXISTS trace_events_dedup
    ON cirislens.trace_events (trace_id, thought_id, event_type, attempt_index, ts);

CREATE INDEX IF NOT EXISTS trace_events_journey
    ON cirislens.trace_events (thought_id, ts);
CREATE INDEX IF NOT EXISTS trace_events_agent_ts
    ON cirislens.trace_events (agent_name, ts DESC);
CREATE INDEX IF NOT EXISTS trace_events_type_ts
    ON cirislens.trace_events (event_type, ts DESC);

-- TimescaleDB hypertable: only created when the extension is present.
-- Pure-Postgres deployments (some Phase 2 agents per FSD §7 #7) skip
-- this; the table works as a plain Postgres table without it.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable(
            'cirislens.trace_events', 'ts',
            chunk_time_interval => INTERVAL '1 day',
            if_not_exists => TRUE
        );
    END IF;
END;
$$;

-- ─── trace_llm_calls: per-LLM-call rows linked to parent event ─────

CREATE TABLE IF NOT EXISTS cirislens.trace_llm_calls (
    call_id              BIGSERIAL,
    trace_id             TEXT        NOT NULL,
    thought_id           TEXT        NOT NULL,
    task_id              TEXT,
    parent_event_id      BIGINT,
    parent_event_type    TEXT,
    parent_attempt_index INT,
    attempt_index        INT         NOT NULL DEFAULT 0,
    ts                   TIMESTAMPTZ NOT NULL,
    duration_ms          DOUBLE PRECISION,
    handler_name         TEXT,
    service_name         TEXT,
    model                TEXT,
    base_url             TEXT,
    response_model       TEXT,
    prompt_tokens        INT,
    completion_tokens    INT,
    prompt_bytes         INT,
    completion_bytes     INT,
    cost_usd             DOUBLE PRECISION,  -- see trace_events.cost_usd note above
    status               TEXT,
    error_class          TEXT,
    attempt_count        INT,
    retry_count          INT,
    prompt_hash          TEXT,
    prompt               TEXT,
    response_text        TEXT,
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

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable(
            'cirislens.trace_llm_calls', 'ts',
            chunk_time_interval => INTERVAL '1 day',
            if_not_exists => TRUE
        );
    END IF;
END;
$$;

-- Compression + retention policies are NOT applied here.
-- TimescaleDB 2.18+ split storage into rowstore vs. columnstore;
-- `add_compression_policy` now requires explicit
-- `ALTER TABLE … SET (timescaledb.enable_columnstore = true)` first,
-- and the right knob varies across the 2.13–2.18 range that real
-- deployments span.
--
-- These policies are *operational concerns*, not structural. The
-- right tuning for a high-volume lens differs from a Pi-class
-- sovereign deployment. The lens deploy-script applies the version-
-- appropriate policies post-migration; CI runs without them so the
-- migration stays version-portable across the supported TimescaleDB
-- range (FSD §7 #7).

-- ─── accord_public_keys: agent verification key directory ──────────
-- Phase 1 source-of-truth for verify (FSD §3.3 step 2). Phase 2's
-- peer-replicate channel (FSD §4.4) extends this with Reticulum-fed
-- announces.

CREATE TABLE IF NOT EXISTS cirislens.accord_public_keys (
    signature_key_id TEXT        PRIMARY KEY,
    public_key_b64   TEXT        NOT NULL,
    agent_id_hash    TEXT,
    registered_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at       TIMESTAMPTZ,
    metadata         JSONB
);

CREATE INDEX IF NOT EXISTS accord_public_keys_agent
    ON cirislens.accord_public_keys (agent_id_hash);
