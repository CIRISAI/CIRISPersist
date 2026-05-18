-- V029 — deferral_reports substrate, SQLite dialect (v1.5.14,
-- CIRISPersist#59 #6).
--
-- Postgres parity (postgres/lens/V029). Dialect translations:
--
--   TIMESTAMPTZ              → TEXT (RFC 3339)
--   JSONB                    → TEXT (raw JSON string)
--   DEFERRABLE INITIALLY DEFERRED FK
--                            → standard FK (SQLite supports
--                              DEFERRABLE clause but only honors
--                              it when PRAGMA defer_foreign_keys=1
--                              is set per-tx; agent callers handle
--                              ordering at the trait surface)
--
-- The 2 persist-only columns (resolved_at, resolution_notes) are
-- nullable — back-compat with the agent's 5-column shape.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here.

CREATE TABLE cirislens_deferral_reports (
    message_id        TEXT PRIMARY KEY,
    task_id           TEXT NOT NULL,
    thought_id        TEXT NOT NULL,
    package           TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    resolved_at       TEXT,
    resolution_notes  TEXT,
    FOREIGN KEY (task_id) REFERENCES cirislens_tasks(task_id),
    FOREIGN KEY (thought_id) REFERENCES cirislens_thoughts(thought_id)
);

-- Hot path #1: per-task reverse lookup.
CREATE INDEX deferral_reports_task
    ON cirislens_deferral_reports (task_id);

-- Hot path #2: per-thought reverse lookup.
CREATE INDEX deferral_reports_thought
    ON cirislens_deferral_reports (thought_id);

-- Hot path #3: `list_active_deferrals` — WA queue of unresolved
-- deferrals, newest-first. Partial index — only unresolved rows
-- carry an entry.
CREATE INDEX deferral_reports_active
    ON cirislens_deferral_reports (created_at DESC)
    WHERE resolved_at IS NULL;
