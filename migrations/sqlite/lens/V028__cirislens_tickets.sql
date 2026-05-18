-- V028 — tickets substrate, SQLite dialect (v1.5.13,
-- CIRISPersist#59 #5).
--
-- Postgres parity (postgres/lens/V028). Dialect translations:
--
--   TIMESTAMPTZ              → TEXT (RFC 3339)
--   JSONB                    → TEXT (raw JSON string)
--   BOOLEAN                  → INTEGER (0 / 1)
--
-- Status vocabulary is LOWERCASE 8-value (`pending | assigned |
-- in_progress | blocked | deferred | completed | cancelled |
-- failed`) — distinct from scheduled_tasks (UPPERCASE 4-value) and
-- partially overlapping with `tasks` (lowercase 6-value). See the
-- PG migration for the rationale.
--
-- Priority is INTEGER 1-10 (default 5).
--
-- `agent_occurrence_id` default is `'__shared__'` (sentinel for
-- cross-occurrence tickets; distinct from `'default'`).
--
-- No FK constraints on this table; `correlation_id` is a free-form
-- string pointer.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here.

CREATE TABLE cirislens_tickets (
    ticket_id              TEXT PRIMARY KEY,
    sop                    TEXT NOT NULL,
    ticket_type            TEXT NOT NULL,
    status                 TEXT NOT NULL
        CHECK (status IN ('pending', 'assigned', 'in_progress',
                          'blocked', 'deferred', 'completed',
                          'cancelled', 'failed')),
    priority               INTEGER NOT NULL DEFAULT 5
        CHECK (priority BETWEEN 1 AND 10),
    email                  TEXT NOT NULL,
    user_identifier        TEXT,
    submitted_at           TEXT NOT NULL,
    deadline               TEXT,
    last_updated           TEXT NOT NULL,
    completed_at           TEXT,
    metadata               TEXT NOT NULL DEFAULT '{}',
    notes                  TEXT,
    automated              INTEGER NOT NULL DEFAULT 0
        CHECK (automated IN (0, 1)),
    correlation_id         TEXT,
    agent_occurrence_id    TEXT NOT NULL DEFAULT '__shared__',
    created_at             TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Hot path #1: per-SOP work queue (occurrence + sop + status +
-- recency).
CREATE INDEX tickets_sop_status_recency
    ON cirislens_tickets (agent_occurrence_id, sop, status, last_updated DESC);

-- Hot path #2: per-user view (email + recency).
CREATE INDEX tickets_email_recency
    ON cirislens_tickets (email, last_updated DESC);

-- Hot path #3: due-deadline scan. Partial — terminal-state tickets
-- excluded.
CREATE INDEX tickets_due_deadline
    ON cirislens_tickets (status, deadline ASC)
    WHERE status NOT IN ('completed', 'cancelled', 'failed');

-- Hot path #4: correlation-keyed reverse lookup. Partial — most
-- tickets aren't tied to a correlation.
CREATE INDEX tickets_correlation
    ON cirislens_tickets (correlation_id)
    WHERE correlation_id IS NOT NULL;
