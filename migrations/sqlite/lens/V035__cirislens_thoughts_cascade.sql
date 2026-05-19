-- V035 — cascade source_task_id FK on cirislens_thoughts, SQLite
-- dialect (v1.5.20, CIRISPersist#60).
--
-- Mirrors postgres/lens/V035. SQLite does NOT support
-- `ALTER TABLE ... DROP CONSTRAINT` or in-place FK modification, so
-- we do the standard 12-step rebuild dance:
--
--   1. PRAGMA defer_foreign_keys = ON (so FK checks run at COMMIT,
--      not on per-statement basis inside this migration)
--   2. CREATE TABLE cirislens_thoughts_new with the new FK shape
--   3. INSERT INTO new SELECT * FROM old
--   4. DROP TABLE old
--   5. ALTER TABLE new RENAME TO original name
--   6. Recreate the three indexes V025 declared on the table
--
-- Refinery wraps each migration in its own transaction; the
-- `defer_foreign_keys` pragma is local to the current transaction
-- per SQLite docs and resets at COMMIT.

PRAGMA defer_foreign_keys = ON;

CREATE TABLE cirislens_thoughts_new (
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
    FOREIGN KEY (source_task_id) REFERENCES cirislens_tasks(task_id)
        ON DELETE CASCADE,
    FOREIGN KEY (parent_thought_id) REFERENCES cirislens_thoughts(thought_id)
);

INSERT INTO cirislens_thoughts_new
SELECT
    thought_id,
    source_task_id,
    channel_id,
    thought_type,
    status,
    created_at,
    updated_at,
    round_number,
    content,
    context_json,
    thought_depth,
    ponder_notes_json,
    parent_thought_id,
    final_action_json,
    agent_occurrence_id
FROM cirislens_thoughts;

DROP TABLE cirislens_thoughts;

ALTER TABLE cirislens_thoughts_new RENAME TO cirislens_thoughts;

CREATE INDEX thoughts_task_recency
    ON cirislens_thoughts (source_task_id, updated_at DESC);

CREATE INDEX thoughts_status_occurrence
    ON cirislens_thoughts (agent_occurrence_id, status, updated_at DESC);

CREATE INDEX thoughts_parent
    ON cirislens_thoughts (parent_thought_id)
    WHERE parent_thought_id IS NOT NULL;
