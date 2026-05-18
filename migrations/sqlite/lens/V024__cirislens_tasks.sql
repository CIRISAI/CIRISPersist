-- V024 — agent tasks substrate, SQLite dialect (v1.5.9, CIRISPersist#59 #1).
--
-- Postgres parity (postgres/lens/V024). Dialect translations:
--
--   TIMESTAMPTZ                  → TEXT (RFC 3339)
--   BOOLEAN                      → INTEGER (0/1)
--   JSONB                        → TEXT (raw JSON string)
--   DEFERRABLE INITIALLY DEFERRED FK
--                                → standard FK (SQLite supports
--                                  DEFERRABLE clause but only
--                                  honors it when PRAGMA
--                                  defer_foreign_keys=1 is set
--                                  per-tx; agent callers handle
--                                  ordering at the trait surface)
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here.

CREATE TABLE cirislens_tasks (
    task_id               TEXT PRIMARY KEY,
    channel_id            TEXT NOT NULL,
    description           TEXT NOT NULL,
    status                TEXT NOT NULL
        CHECK (status IN ('pending', 'active', 'completed',
                          'failed', 'cancelled', 'deferred')),
    priority              INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    parent_task_id        TEXT,
    context_json          TEXT,
    outcome_json          TEXT,
    retry_count           INTEGER NOT NULL DEFAULT 0
        CHECK (retry_count >= 0),
    signed_by             TEXT,
    signature             TEXT,
    signed_at             TEXT,
    updated_info_available INTEGER NOT NULL DEFAULT 0,
    updated_info_content  TEXT,
    agent_occurrence_id   TEXT NOT NULL DEFAULT 'default',
    images_json           TEXT,
    FOREIGN KEY (parent_task_id) REFERENCES cirislens_tasks(task_id)
);

-- Hot path: list_tasks happy path (occurrence + status + recency).
CREATE INDEX tasks_status_occurrence
    ON cirislens_tasks (agent_occurrence_id, status, updated_at DESC);

-- Channel-scoped recency scan.
CREATE INDEX tasks_channel
    ON cirislens_tasks (channel_id, updated_at DESC);

-- Reverse-lookup: find a parent's children. NULL-skipping partial.
CREATE INDEX tasks_parent
    ON cirislens_tasks (parent_task_id)
    WHERE parent_task_id IS NOT NULL;
