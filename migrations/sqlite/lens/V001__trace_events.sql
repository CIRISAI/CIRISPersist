-- V001 — trace_events + trace_llm_calls + accord_public_keys (SQLite).
--
-- SQLite translation of migrations/postgres/lens/V001__trace_events.sql.
-- Same logical schema; different physical types because SQLite is
-- dynamically typed (type affinity, not enforcement) and lacks several
-- Postgres types we use. Mapping decisions:
--
--   BIGSERIAL          → INTEGER PRIMARY KEY AUTOINCREMENT (single-col PK;
--                        postgres' composite (event_id, ts) is for
--                        TimescaleDB partitioning, which SQLite doesn't
--                        have — SQLite gets a plain rowid-backed PK)
--   TIMESTAMPTZ        → TEXT (ISO-8601 with offset; v0.1.8's
--                        WireDateTime doctrine preserves wire bytes
--                        verbatim, which is exactly what TEXT storage
--                        gives us)
--   JSONB              → TEXT (SQLite's json1 extension can query TEXT
--                        as JSON; we never re-encode payload bytes)
--   BOOLEAN            → INTEGER (0/1; SQLite has no native bool)
--   DOUBLE PRECISION,
--   NUMERIC(10,6)      → REAL
--   INT, BIGINT        → INTEGER (SQLite's INTEGER is variable-width,
--                        up to 8 bytes — covers BIGINT range natively)
--   CREATE SCHEMA …,
--   cirislens.table    → dropped; SQLite has no schemas. Tables live
--                        in the connection's default namespace.
--   DEFAULT NOW()      → DEFAULT CURRENT_TIMESTAMP (ISO-8601 UTC; no
--                        timezone offset emitted, but matches the
--                        TIMESTAMPTZ string-form for our usage)
--   IS DISTINCT FROM   → IS NOT (SQLite's NULL-safe comparison)
--   TimescaleDB hypertable creation — skipped entirely. SQLite has no
--                        partitioning; ts indexes give us the read
--                        patterns FSD §3.5 names.
--
-- Mission alignment (MISSION.md §2 — `store/`): same Backend trait,
-- different substrate. The decompose path produces TraceEventRow
-- regardless of backend; the SQL writer here adapts row → SQL.
-- THREAT_MODEL.md AV-9 dedup-tuple shape is identical to the postgres
-- index — `(agent_id_hash, trace_id, thought_id, event_type,
-- attempt_index, ts)`.

-- ─── trace_events: one row per ReasoningEvent broadcast ────────────

CREATE TABLE IF NOT EXISTS trace_events (
    event_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    trace_id        TEXT    NOT NULL,
    thought_id      TEXT    NOT NULL,
    task_id         TEXT,
    step_point      TEXT,
    event_type      TEXT    NOT NULL,
    attempt_index   INTEGER NOT NULL DEFAULT 0,
    ts              TEXT    NOT NULL,
    agent_name      TEXT,
    agent_id_hash   TEXT,
    cognitive_state TEXT,
    trace_level     TEXT    NOT NULL,
    payload         TEXT    NOT NULL,
    cost_llm_calls  INTEGER,
    cost_tokens     INTEGER,
    -- f64-shaped column (see postgres V001 note about
    -- DOUBLE PRECISION choice). REAL in SQLite.
    cost_usd        REAL,
    signature       TEXT,
    signing_key_id  TEXT,
    signature_verified INTEGER NOT NULL DEFAULT 0,
    schema_version  TEXT,
    pii_scrubbed    INTEGER NOT NULL DEFAULT 0,
    audit_sequence_number INTEGER,
    audit_entry_hash      TEXT,
    audit_signature       TEXT
);

-- Dedup index — same shape as postgres V001 trace_events_dedup.
-- THREAT_MODEL.md AV-9: includes agent_id_hash so a malicious agent
-- reusing another agent's thought_id shape cannot DOS the victim's
-- traces.
CREATE UNIQUE INDEX IF NOT EXISTS trace_events_dedup
    ON trace_events (agent_id_hash, trace_id, thought_id, event_type, attempt_index, ts);

CREATE INDEX IF NOT EXISTS trace_events_journey
    ON trace_events (thought_id, ts);
CREATE INDEX IF NOT EXISTS trace_events_agent_ts
    ON trace_events (agent_name, ts DESC);
CREATE INDEX IF NOT EXISTS trace_events_type_ts
    ON trace_events (event_type, ts DESC);
CREATE INDEX IF NOT EXISTS trace_events_audit_seq
    ON trace_events (audit_sequence_number)
    WHERE audit_sequence_number IS NOT NULL;

-- ─── trace_llm_calls: per-LLM-call rows linked to parent event ─────

CREATE TABLE IF NOT EXISTS trace_llm_calls (
    call_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    trace_id             TEXT    NOT NULL,
    thought_id           TEXT    NOT NULL,
    task_id              TEXT,
    parent_event_id      INTEGER,
    parent_event_type    TEXT,
    parent_attempt_index INTEGER,
    attempt_index        INTEGER NOT NULL DEFAULT 0,
    ts                   TEXT    NOT NULL,
    duration_ms          REAL,
    handler_name         TEXT,
    service_name         TEXT,
    model                TEXT,
    base_url             TEXT,
    response_model       TEXT,
    prompt_tokens        INTEGER,
    completion_tokens    INTEGER,
    prompt_bytes         INTEGER,
    completion_bytes     INTEGER,
    cost_usd             REAL,
    status               TEXT,
    error_class          TEXT,
    attempt_count        INTEGER,
    retry_count          INTEGER,
    prompt_hash          TEXT,
    prompt               TEXT,
    response_text        TEXT
);

CREATE INDEX IF NOT EXISTS trace_llm_calls_thought
    ON trace_llm_calls (thought_id, ts);
CREATE INDEX IF NOT EXISTS trace_llm_calls_parent
    ON trace_llm_calls (parent_event_id);
CREATE INDEX IF NOT EXISTS trace_llm_calls_model_ts
    ON trace_llm_calls (model, ts DESC);
-- Postgres uses `IS DISTINCT FROM 'ok'` here; SQLite's `IS NOT`
-- handles NULL the same way (a NULL status passes the filter).
CREATE INDEX IF NOT EXISTS trace_llm_calls_status_ts
    ON trace_llm_calls (status, ts DESC) WHERE status IS NOT 'ok';

-- ─── accord_public_keys: agent verification key directory ──────────
--
-- Lens-canonical shape (matches CIRISLens sql/011_accord_public_keys
-- + sql/022_revocation, modulo SQLite type translations). Phase 1
-- source-of-truth for verify (FSD §3.3 step 2). Phase 2's
-- peer-replicate channel (FSD §4.4) extends this with Reticulum-fed
-- announces.
--
-- THREAT_MODEL.md AV-11: revoked_at + revoked_reason + added_by are
-- the rotation-audit surface — preserved in the SQLite shape.

CREATE TABLE IF NOT EXISTS accord_public_keys (
    key_id            TEXT    PRIMARY KEY,
    public_key_base64 TEXT    NOT NULL,
    algorithm         TEXT,
    description       TEXT,
    -- DEFAULT CURRENT_TIMESTAMP emits ISO-8601 UTC (no offset);
    -- matches the TEXT-as-TIMESTAMPTZ shape across the schema.
    created_at        TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at        TEXT,
    revoked_at        TEXT,
    revoked_reason    TEXT,
    added_by          TEXT
);
