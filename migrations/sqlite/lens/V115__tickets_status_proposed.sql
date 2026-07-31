-- V115 — admit 'proposed' into cirislens_tickets.status, SQLite dialect
-- v24.1.0 (CIRISPersist#560)
--
-- POSTGRES PARITY: migrations/postgres/lens/V115__tickets_status_proposed.sql
-- (same value admitted there; Postgres has DROP CONSTRAINT so its twin is four
-- lines and this one is a table rebuild. See that file for the FULL rationale —
-- why the vocabulary gains a value instead of becoming an open string, and why
-- `blocked` + a `__proposal__` metadata marker was the wrong shape.)
--
-- THE SHORT VERSION
-- -----------------
-- V028's 8-value set had no way to say "an agent PROPOSED this work and no
-- human has authorized it yet". `blocked` means *work that is stuck*; that is
-- a different operational state, and an operator reading a blocked-ticket
-- queue could not tell the two apart.
--
-- Nothing is removed and no row changes: the eight existing values remain
-- admissible with identical meaning.
--
-- HOW (the SQLite table-rebuild recipe)
-- -------------------------------------
-- SQLite bakes table-level CHECKs into CREATE TABLE and has no
-- `ALTER TABLE ... DROP CONSTRAINT`, so the table is rebuilt (the V020 / V035 /
-- V061 / V114 recipe). `cirislens_tickets` is the easy case:
--   * nothing REFERENCES it (`correlation_id` is a free-form pointer, declared
--     with no FK — verified across the whole migration set), so the DROP fires
--     no cascade and nothing needs staging;
--   * it carries no triggers;
--   * its four indexes are recreated verbatim below.
-- `PRAGMA` statements are no-ops inside refinery's per-migration transaction,
-- which is fine here — with no inbound FKs there is nothing to defer.
--
-- Every other CHECK is reproduced VERBATIM (priority BETWEEN 1 AND 10,
-- automated IN (0,1)); a rebuild is the one moment a constraint can be
-- silently widened by transcription, so they are copied, not restated.

CREATE TABLE cirislens_tickets_new (
    ticket_id              TEXT PRIMARY KEY,
    sop                    TEXT NOT NULL,
    ticket_type            TEXT NOT NULL,
    -- v24.1.0 (CIRISPersist#560) — 'proposed' joins the set.
    status                 TEXT NOT NULL
        CHECK (status IN ('proposed', 'pending', 'assigned', 'in_progress',
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

INSERT INTO cirislens_tickets_new (
    ticket_id, sop, ticket_type, status, priority, email, user_identifier,
    submitted_at, deadline, last_updated, completed_at, metadata, notes,
    automated, correlation_id, agent_occurrence_id, created_at)
SELECT
    ticket_id, sop, ticket_type, status, priority, email, user_identifier,
    submitted_at, deadline, last_updated, completed_at, metadata, notes,
    automated, correlation_id, agent_occurrence_id, created_at
FROM cirislens_tickets;

DROP TABLE cirislens_tickets;

ALTER TABLE cirislens_tickets_new RENAME TO cirislens_tickets;

-- The four V028 indexes, verbatim. The `tickets_due_deadline` predicate
-- excludes the three TERMINAL states and is DELIBERATELY unchanged:
-- `proposed` is not terminal (it precedes the lifecycle rather than ending
-- it), and a partial index gates planner eligibility, never result sets.
CREATE INDEX tickets_sop_status_recency
    ON cirislens_tickets (agent_occurrence_id, sop, status, last_updated DESC);

CREATE INDEX tickets_email_recency
    ON cirislens_tickets (email, last_updated DESC);

CREATE INDEX tickets_due_deadline
    ON cirislens_tickets (status, deadline ASC)
    WHERE status NOT IN ('completed', 'cancelled', 'failed');

CREATE INDEX tickets_correlation
    ON cirislens_tickets (correlation_id)
    WHERE correlation_id IS NOT NULL;
