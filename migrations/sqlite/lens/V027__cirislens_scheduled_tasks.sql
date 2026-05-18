-- V027 — scheduled tasks substrate, SQLite dialect (v1.5.12,
-- CIRISPersist#59 #4).
--
-- Postgres parity (postgres/lens/V027). Dialect translations:
--
--   TIMESTAMPTZ                  → TEXT (RFC 3339)
--   JSONB                        → TEXT (raw JSON string)
--   DEFERRABLE INITIALLY DEFERRED FK
--                                → standard FK (SQLite enforces
--                                  immediately by default; the
--                                  DEFERRABLE clause is honored only
--                                  with `PRAGMA defer_foreign_keys=1`
--                                  per-tx — agent callers handle
--                                  ordering at the trait surface).
--
-- Status vocabulary IS UPPERCASE on this table (`PENDING | ACTIVE |
-- COMPLETE | FAILED`) — distinct from `tasks` / `thoughts` lowercase
-- vocabularies. See the PG migration for the rationale.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here.

CREATE TABLE cirislens_scheduled_tasks (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    goal_description      TEXT NOT NULL,
    status                TEXT NOT NULL
        CHECK (status IN ('PENDING', 'ACTIVE', 'COMPLETE', 'FAILED')),
    defer_until           TEXT,
    schedule_cron         TEXT,
    trigger_prompt        TEXT NOT NULL,
    origin_thought_id     TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    last_triggered_at     TEXT,
    next_trigger_at       TEXT,
    deferral_count        INTEGER NOT NULL DEFAULT 0
        CHECK (deferral_count >= 0),
    deferral_history      TEXT,
    created_by_agent      TEXT,
    agent_occurrence_id   TEXT NOT NULL DEFAULT 'default',
    FOREIGN KEY (origin_thought_id) REFERENCES cirislens_thoughts(thought_id)
);

-- Hot path #1: scheduler tick. Partial index.
CREATE INDEX scheduled_tasks_due
    ON cirislens_scheduled_tasks (agent_occurrence_id, next_trigger_at)
    WHERE next_trigger_at IS NOT NULL
      AND status IN ('PENDING', 'ACTIVE');

-- Hot path #2: list-by-status (status + occurrence + recency).
CREATE INDEX scheduled_tasks_status_occurrence
    ON cirislens_scheduled_tasks (agent_occurrence_id, status, created_at DESC);

-- Hot path #3: reverse-lookup by originating thought.
CREATE INDEX scheduled_tasks_origin
    ON cirislens_scheduled_tasks (origin_thought_id);
