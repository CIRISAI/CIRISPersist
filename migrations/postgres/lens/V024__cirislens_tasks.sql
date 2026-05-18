-- V024 — agent tasks substrate (v1.5.9, CIRISPersist#59 #1).
--
-- First of 11 substrate absorptions ending CIRISAgent's direct
-- libsqlite access to `ciris_engine.db`. Mirrors CIRISAgent 2.8.13
-- `tasks` table with PG-dialect translations:
--
--   TEXT timestamp columns   → TIMESTAMPTZ
--   INTEGER boolean columns  → BOOLEAN
--   JSON-string columns      → JSONB
--   parent_task_id self-FK   → DEFERRABLE INITIALLY DEFERRED so a
--                              bulk INSERT carrying parent+child in
--                              the same tx (or a self-cycle workload
--                              for the agent's planning graphs)
--                              passes constraint check at COMMIT.
--
-- Status vocabulary (`pending`, `active`, `completed`, `failed`,
-- `cancelled`, `deferred`) inferred from CIRISAgent task lifecycle
-- code; if the agent vocabulary diverges, update the CHECK
-- constraint here + `TaskStatus::as_sql_str` + `parse_str` in lockstep.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens.tasks (
    task_id               TEXT PRIMARY KEY,
    channel_id            TEXT NOT NULL,
    description           TEXT NOT NULL,
    status                TEXT NOT NULL
        CHECK (status IN ('pending', 'active', 'completed',
                          'failed', 'cancelled', 'deferred')),
    priority              INTEGER NOT NULL DEFAULT 0,
    created_at            TIMESTAMPTZ NOT NULL,
    updated_at            TIMESTAMPTZ NOT NULL,
    parent_task_id        TEXT,
    context_json          JSONB,
    outcome_json          JSONB,
    retry_count           INTEGER NOT NULL DEFAULT 0
        CHECK (retry_count >= 0),
    signed_by             TEXT,
    signature             TEXT,
    signed_at             TIMESTAMPTZ,
    updated_info_available BOOLEAN NOT NULL DEFAULT FALSE,
    updated_info_content  TEXT,
    agent_occurrence_id   TEXT NOT NULL DEFAULT 'default',
    images_json           JSONB,
    -- Self-FK on parent_task_id. DEFERRABLE INITIALLY DEFERRED
    -- lets bulk INSERT in topological-cycle-tolerant order pass
    -- constraint check at COMMIT — required for the agent's
    -- planning-graph workloads where a parent + child land in
    -- the same tx.
    CONSTRAINT tasks_parent_fk FOREIGN KEY (parent_task_id)
        REFERENCES cirislens.tasks(task_id) DEFERRABLE INITIALLY DEFERRED
);

-- Hot path: list_tasks happy path (occurrence + status + recency).
CREATE INDEX tasks_status_occurrence
    ON cirislens.tasks (agent_occurrence_id, status, updated_at DESC);

-- Channel-scoped recency scan.
CREATE INDEX tasks_channel
    ON cirislens.tasks (channel_id, updated_at DESC);

-- Reverse-lookup: find a parent's children. NULL-skipping partial.
CREATE INDEX tasks_parent
    ON cirislens.tasks (parent_task_id)
    WHERE parent_task_id IS NOT NULL;

COMMENT ON TABLE cirislens.tasks IS
    'v1.5.9 (CIRISPersist#59 #1) — agent tasks substrate. Absorbs CIRISAgent ciris_engine.db.tasks. Ends dual-libsqlite access pattern.';
