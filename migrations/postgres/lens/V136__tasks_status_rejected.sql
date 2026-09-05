-- V136 — admit 'rejected' into cirislens.tasks.status
-- v41.2.0 (CIRISPersist#810, CIRISAgent#1077)
--
-- SQLITE PARITY: migrations/sqlite/lens/V136__tasks_status_rejected.sql
-- (same value admitted there — but SQLite bakes table-level CHECKs into
-- CREATE TABLE and has no DROP CONSTRAINT, so its twin is a table rebuild
-- and this one is four lines. That twin is also the HARD rebuild case:
-- see its header for why `cirislens_thoughts` has to be staged across the
-- drop.)
--
-- WHAT AND WHY
-- ------------
-- V024 declared a 6-value vocabulary and its comment claimed it "mirrors
-- the CIRISAgent 2.8.13 task state machine". It mirrors something else.
-- The consumer enum, `ciris_engine.schemas.runtime.enums.TaskStatus`, is:
--
--     pending / active / completed / failed / deferred / REJECTED
--
-- V024 has `cancelled`, which the agent's enum has never had, and is
-- MISSING `rejected`, which the agent's `reject` handler writes.
--
-- The direction of that mismatch is what makes it a production defect
-- rather than a cosmetic one. A value persist HAS that the consumer does
-- not (`cancelled`) is inert. A value persist LACKS is a wedge: persist
-- refuses `rejected` exactly the way it refuses a typo, the agent logs the
-- ValueError and continues, the write never lands, and the task stays
-- `active` with nothing to retry it. CIRISAgent#1077 observed three wakeup
-- step tasks stuck that way in a single boot on a fresh `datum`, and
-- argues it plausibly explains CIRISAgent#1069 (WAKEUP spinning 15,938
-- rounds over 22h producing 0 thoughts) and CIRISAgent#1070 (children-first
-- delete failing, because a stuck active task keeps thoughts holding the
-- FK).
--
-- The invariant this restores, and which
-- `every_status_the_agent_can_write_round_trips` now pins as literals:
-- **persist's status vocabulary is a SUPERSET of the consumer enum it
-- mirrors.** It grows when the consumer's grows. It never shrinks.
--
-- The vocabulary stays CLOSED rather than becoming an open validated
-- string. A closed set is what makes an unknown status a refusal instead
-- of a silently stored typo — the V115 argument, unchanged. The cost of a
-- closed set is exactly this migration, and that cost is worth paying;
-- what was not worth paying is discovering the gap in production.
--
-- Nothing is removed and no row changes: the six existing values remain
-- admissible with identical meaning, so every stored task is untouched and
-- this migration is safe to apply under load.
--
-- `rejected` is deliberately NOT folded onto `failed` or `cancelled`. A
-- rejected task was declined; a failed task ran and did not succeed; a
-- deferred task is waiting on a wise authority. Mapping agent-side would
-- store a true-looking row that lost the outcome, which is worse than the
-- refusal it replaces.
--
-- The `tasks_status_occurrence` index is DELIBERATELY not modified: it is
-- a plain three-column index with no predicate, so a seventh admissible
-- value needs nothing from it.
--
-- Dropped by DISCOVERY, not by name — the V114/V115 lesson. V024 declares
-- the CHECK inline, so its name is whatever Postgres generated
-- (`tasks_status_check` on every database we have seen). Looking it up in
-- `pg_constraint` means a deployment whose constraint was ever renamed, or
-- restored from a dump under a different name, is migrated correctly
-- rather than silently left enforcing the 6-value set — which would make
-- `rejected` a runtime 23514 on exactly the deployments that took the
-- trouble to rename things. Matched on the COLUMN it constrains, which is
-- stable.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here.

DO $$
DECLARE
    conname_to_drop text;
BEGIN
    SELECT c.conname INTO conname_to_drop
    FROM pg_constraint c
    JOIN pg_class t     ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = 'cirislens'
      AND t.relname = 'tasks'
      AND c.contype = 'c'
      AND c.conkey = ARRAY[
            (SELECT a.attnum FROM pg_attribute a
              WHERE a.attrelid = t.oid AND a.attname = 'status')
          ]::smallint[];

    IF conname_to_drop IS NOT NULL THEN
        EXECUTE format(
            'ALTER TABLE cirislens.tasks DROP CONSTRAINT %I',
            conname_to_drop);
    END IF;
END
$$;

ALTER TABLE cirislens.tasks
    ADD CONSTRAINT tasks_status_check
    CHECK (status IN ('pending', 'active', 'completed',
                      'failed', 'cancelled', 'deferred',
                      'rejected'));

COMMENT ON COLUMN cirislens.tasks.status IS
    'v41.2.0 (CIRISPersist#810) — closed 7-value set. SUPERSET of CIRISAgent''s TaskStatus (pending/active/completed/failed/deferred/rejected); ''cancelled'' is persist-only. Grows with the consumer enum, never shrinks: a missing value wedges the task active forever (CIRISAgent#1077).';
