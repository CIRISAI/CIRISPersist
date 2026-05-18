-- V028 — tickets substrate (v1.5.13, CIRISPersist#59 #5).
--
-- Fifth of 11 substrate absorptions ending CIRISAgent's direct
-- libsqlite access to `ciris_engine.db`. Mirrors CIRISAgent 2.8.13
-- `tickets` table with PG-dialect translations:
--
--   TEXT timestamp columns   → TIMESTAMPTZ (submitted_at /
--                              deadline / last_updated /
--                              completed_at / created_at)
--   JSON-string columns      → JSONB (metadata)
--   INTEGER boolean columns  → BOOLEAN (automated)
--
-- Status vocabulary is LOWERCASE 8-value (`pending | assigned |
-- in_progress | blocked | deferred | completed | cancelled |
-- failed`) — distinct from scheduled_tasks (UPPERCASE 4-value) and
-- partially overlapping with `tasks` (lowercase 6-value). The
-- agent's `tickets.status` column declares this vocabulary verbatim;
-- persist follows it. Note mixed snake_case for `in_progress`.
--
-- Priority is INTEGER 1-10 (default 5).
--
-- `agent_occurrence_id` default is `'__shared__'` (sentinel for
-- cross-occurrence tickets; distinct from the `'default'` sentinel
-- the other substrates use for single-occurrence callers). Tickets
-- are typically cross-occurrence work items routed to specific
-- agents, not occurrence-private state.
--
-- No FK constraints on this table; `correlation_id` is a free-form
-- string pointer that may target a span in another substrate or
-- another occurrence's correlations.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens.tickets (
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
    submitted_at           TIMESTAMPTZ NOT NULL,
    deadline               TIMESTAMPTZ,
    last_updated           TIMESTAMPTZ NOT NULL,
    completed_at           TIMESTAMPTZ,
    metadata               JSONB NOT NULL DEFAULT '{}'::JSONB,
    notes                  TEXT,
    automated              BOOLEAN NOT NULL DEFAULT FALSE,
    correlation_id         TEXT,
    agent_occurrence_id    TEXT NOT NULL DEFAULT '__shared__',
    created_at             TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Hot path #1: per-SOP work queue ordered by recency, scoped per
-- occurrence + status. `WHERE status = ...` cuts the index leaf set
-- and `last_updated DESC` matches the agent's "most-recent first"
-- queue scan.
CREATE INDEX tickets_sop_status_recency
    ON cirislens.tickets (agent_occurrence_id, sop, status, last_updated DESC);

-- Hot path #2: per-user view ("show me my tickets"), ordered by
-- recency. Covers both submitter (`email`) and assignee
-- (`user_identifier`) queries — assignee lookup uses a separate
-- partial index below.
CREATE INDEX tickets_email_recency
    ON cirislens.tickets (email, last_updated DESC);

-- Hot path #3: due-deadline scan. Partial index — only tickets that
-- could still come due carry an entry. Terminal-state tickets
-- (completed / cancelled / failed) are excluded.
CREATE INDEX tickets_due_deadline
    ON cirislens.tickets (status, deadline ASC)
    WHERE status NOT IN ('completed', 'cancelled', 'failed');

-- Hot path #4: correlation-keyed reverse lookup. Partial index —
-- most tickets aren't tied to a correlation, so the leaf set stays
-- small.
CREATE INDEX tickets_correlation
    ON cirislens.tickets (correlation_id)
    WHERE correlation_id IS NOT NULL;

COMMENT ON TABLE cirislens.tickets IS
    'v1.5.13 (CIRISPersist#59 #5) — tickets substrate. Absorbs CIRISAgent ciris_engine.db.tickets. Status vocabulary is LOWERCASE 8-value (pending/assigned/in_progress/blocked/deferred/completed/cancelled/failed); priority 1-10 (default 5); agent_occurrence_id default ''__shared__'' (cross-occurrence work items).';
