-- V025 — agent thoughts substrate (v1.5.10, CIRISPersist#59 #2).
--
-- Second of 11 substrate absorptions ending CIRISAgent's direct
-- libsqlite access to `ciris_engine.db`. Mirrors CIRISAgent 2.8.13
-- `thoughts` table with PG-dialect translations:
--
--   TEXT timestamp columns   → TIMESTAMPTZ
--   JSON-string columns      → JSONB
--   source_task_id FK        → REFERENCES cirislens.tasks(task_id)
--                              DEFERRABLE INITIALLY DEFERRED so a
--                              caller writing parent task + first
--                              thought in the same tx passes
--                              constraint check at COMMIT.
--   parent_thought_id self-FK → DEFERRABLE INITIALLY DEFERRED so a
--                              caller writing a thought chain top-
--                              down or bottom-up in one tx
--                              succeeds.
--
-- Status vocabulary (`pending | processing | completed | failed |
-- deferred`) lifted verbatim from CIRISAgent
-- `ciris_engine/schemas/runtime/enums.py::ThoughtStatus`. The
-- ThoughtType column is left open-text (TEXT DEFAULT 'standard')
-- per the agent's free-vocabulary enum — 20+ values today and the
-- list is the agent's own design space; persist tracks the agent
-- rather than constraining it. Default lines up with the agent's
-- `ThoughtType.STANDARD = "standard"`.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens.thoughts (
    thought_id            TEXT PRIMARY KEY,
    source_task_id        TEXT NOT NULL,
    channel_id            TEXT,
    thought_type          TEXT NOT NULL DEFAULT 'standard',
    status                TEXT NOT NULL
        CHECK (status IN ('pending', 'processing', 'completed',
                          'failed', 'deferred')),
    created_at            TIMESTAMPTZ NOT NULL,
    updated_at            TIMESTAMPTZ NOT NULL,
    round_number          INTEGER NOT NULL DEFAULT 0
        CHECK (round_number >= 0),
    content               TEXT NOT NULL,
    context_json          JSONB,
    thought_depth         INTEGER NOT NULL DEFAULT 0
        CHECK (thought_depth >= 0),
    ponder_notes_json     JSONB,
    parent_thought_id     TEXT,
    final_action_json     JSONB,
    agent_occurrence_id   TEXT NOT NULL DEFAULT 'default',
    -- FK to tasks. DEFERRABLE INITIALLY DEFERRED so a tx can write
    -- the parent task + its first thought atomically — constraint
    -- check fires at COMMIT, by which point both rows exist.
    CONSTRAINT thoughts_task_fk FOREIGN KEY (source_task_id)
        REFERENCES cirislens.tasks(task_id) DEFERRABLE INITIALLY DEFERRED,
    -- Self-FK on parent_thought_id. Same DEFERRABLE rationale as the
    -- tasks substrate: an agent reasoning chain can write parent +
    -- child in one tx and have constraint check pass at COMMIT.
    CONSTRAINT thoughts_parent_fk FOREIGN KEY (parent_thought_id)
        REFERENCES cirislens.thoughts(thought_id) DEFERRABLE INITIALLY DEFERRED
);

-- Hot path: list_thoughts by parent task (chain walk per task).
CREATE INDEX thoughts_task_recency
    ON cirislens.thoughts (source_task_id, updated_at DESC);

-- list-by-status happy path (occurrence + status + recency).
CREATE INDEX thoughts_status_occurrence
    ON cirislens.thoughts (agent_occurrence_id, status, updated_at DESC);

-- Reverse-lookup: find a parent's children. NULL-skipping partial
-- so the index only carries rows that participate in a parent-
-- chain — `get_descendants` recursive CTE walks this from the root.
CREATE INDEX thoughts_parent
    ON cirislens.thoughts (parent_thought_id)
    WHERE parent_thought_id IS NOT NULL;

COMMENT ON TABLE cirislens.thoughts IS
    'v1.5.10 (CIRISPersist#59 #2) — agent thoughts substrate. Absorbs CIRISAgent ciris_engine.db.thoughts. FKs to cirislens.tasks + self-FK both DEFERRABLE.';
