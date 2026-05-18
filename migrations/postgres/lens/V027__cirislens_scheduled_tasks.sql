-- V027 — scheduled tasks substrate (v1.5.12, CIRISPersist#59 #4).
--
-- Fourth of 11 substrate absorptions ending CIRISAgent's direct
-- libsqlite access to `ciris_engine.db`. Mirrors CIRISAgent 2.8.13
-- `scheduled_tasks` table with PG-dialect translations:
--
--   TEXT timestamp columns   → TIMESTAMPTZ (defer_until /
--                              created_at / last_triggered_at /
--                              next_trigger_at)
--   JSON-string columns      → JSONB (deferral_history)
--   origin_thought_id FK     → REFERENCES cirislens.thoughts(thought_id)
--                              DEFERRABLE INITIALLY DEFERRED so a
--                              caller writing the originating
--                              thought + its scheduled task in the
--                              same tx passes the constraint check
--                              at COMMIT.
--
-- Status vocabulary IS UPPERCASE on this table (`PENDING | ACTIVE |
-- COMPLETE | FAILED`) — distinct from the `tasks` / `thoughts`
-- substrates which use lowercase vocabularies. The agent's
-- `scheduled_tasks.status` column declares the uppercase set;
-- persist follows the agent's vocabulary verbatim per the spec.
-- Note also that the value is `COMPLETE` (not `completed`) — the
-- agent's scheduler uses the four-value set above.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens.scheduled_tasks (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    goal_description      TEXT NOT NULL,
    status                TEXT NOT NULL
        CHECK (status IN ('PENDING', 'ACTIVE', 'COMPLETE', 'FAILED')),
    defer_until           TIMESTAMPTZ,
    schedule_cron         TEXT,
    trigger_prompt        TEXT NOT NULL,
    origin_thought_id     TEXT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL,
    last_triggered_at     TIMESTAMPTZ,
    next_trigger_at       TIMESTAMPTZ,
    deferral_count        INTEGER NOT NULL DEFAULT 0
        CHECK (deferral_count >= 0),
    deferral_history      JSONB,
    created_by_agent      TEXT,
    agent_occurrence_id   TEXT NOT NULL DEFAULT 'default',
    -- FK to thoughts. DEFERRABLE INITIALLY DEFERRED so a tx can
    -- write the originating thought + its scheduled task atomically
    -- — constraint check fires at COMMIT.
    CONSTRAINT scheduled_tasks_origin_thought_fk
        FOREIGN KEY (origin_thought_id) REFERENCES cirislens.thoughts(thought_id)
        DEFERRABLE INITIALLY DEFERRED
);

-- Hot path #1: scheduler tick. Find due tasks (next_trigger_at <=
-- now AND status IN (PENDING, ACTIVE)) scoped per occurrence. Partial
-- index — only rows that participate in a future tick carry an entry.
CREATE INDEX scheduled_tasks_due
    ON cirislens.scheduled_tasks (agent_occurrence_id, next_trigger_at)
    WHERE next_trigger_at IS NOT NULL
      AND status IN ('PENDING', 'ACTIVE');

-- Hot path #2: list-by-status. Status + occurrence + creation
-- recency (e.g., "show me the FAILED scheduled tasks on occ-X").
CREATE INDEX scheduled_tasks_status_occurrence
    ON cirislens.scheduled_tasks (agent_occurrence_id, status, created_at DESC);

-- Hot path #3: reverse-lookup by originating thought. Find every
-- scheduled task descended from a given thought.
CREATE INDEX scheduled_tasks_origin
    ON cirislens.scheduled_tasks (origin_thought_id);

COMMENT ON TABLE cirislens.scheduled_tasks IS
    'v1.5.12 (CIRISPersist#59 #4) — scheduled tasks substrate. Absorbs CIRISAgent ciris_engine.db.scheduled_tasks. Status vocabulary is UPPERCASE (PENDING/ACTIVE/COMPLETE/FAILED). FK to cirislens.thoughts DEFERRABLE.';
