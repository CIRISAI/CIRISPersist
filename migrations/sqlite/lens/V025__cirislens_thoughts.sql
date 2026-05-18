-- V025 — agent thoughts substrate, SQLite dialect (v1.5.10, CIRISPersist#59 #2).
--
-- Postgres parity (postgres/lens/V025). Dialect translations:
--
--   TIMESTAMPTZ                  → TEXT (RFC 3339)
--   JSONB                        → TEXT (raw JSON string)
--   DEFERRABLE INITIALLY DEFERRED FK
--                                → standard FK (SQLite supports
--                                  DEFERRABLE clause but only
--                                  honors it when PRAGMA
--                                  defer_foreign_keys=1 is set
--                                  per-tx; agent callers handle
--                                  ordering at the trait surface)
--
-- ThoughtType is open-text (TEXT NOT NULL DEFAULT 'standard') per
-- CIRISAgent's 20+-value `ThoughtType` enum design space.
-- ThoughtStatus is closed-set per the agent's `ThoughtStatus`
-- vocabulary (5 values).
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here.

CREATE TABLE cirislens_thoughts (
    thought_id            TEXT PRIMARY KEY,
    source_task_id        TEXT NOT NULL,
    channel_id            TEXT,
    thought_type          TEXT NOT NULL DEFAULT 'standard',
    status                TEXT NOT NULL
        CHECK (status IN ('pending', 'processing', 'completed',
                          'failed', 'deferred')),
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    round_number          INTEGER NOT NULL DEFAULT 0
        CHECK (round_number >= 0),
    content               TEXT NOT NULL,
    context_json          TEXT,
    thought_depth         INTEGER NOT NULL DEFAULT 0
        CHECK (thought_depth >= 0),
    ponder_notes_json     TEXT,
    parent_thought_id     TEXT,
    final_action_json     TEXT,
    agent_occurrence_id   TEXT NOT NULL DEFAULT 'default',
    FOREIGN KEY (source_task_id) REFERENCES cirislens_tasks(task_id),
    FOREIGN KEY (parent_thought_id) REFERENCES cirislens_thoughts(thought_id)
);

-- Hot path: list_thoughts by parent task (chain walk per task).
CREATE INDEX thoughts_task_recency
    ON cirislens_thoughts (source_task_id, updated_at DESC);

-- list-by-status happy path (occurrence + status + recency).
CREATE INDEX thoughts_status_occurrence
    ON cirislens_thoughts (agent_occurrence_id, status, updated_at DESC);

-- Reverse-lookup: find a parent's children. NULL-skipping partial.
CREATE INDEX thoughts_parent
    ON cirislens_thoughts (parent_thought_id)
    WHERE parent_thought_id IS NOT NULL;
