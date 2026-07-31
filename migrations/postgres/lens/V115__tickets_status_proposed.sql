-- V115 — admit 'proposed' into cirislens.tickets.status
-- v24.1.0 (CIRISPersist#560)
--
-- SQLITE PARITY: migrations/sqlite/lens/V115__tickets_status_proposed.sql
-- (same value admitted there — but SQLite bakes table-level CHECKs into
-- CREATE TABLE and has no DROP CONSTRAINT, so its twin is a table rebuild
-- and this one is four lines.)
--
-- WHAT AND WHY
-- ------------
-- V028 declared an 8-value status vocabulary, copied verbatim from the
-- agent's own `tickets.status` column. It has no way to say "an agent
-- PROPOSED this work and no human has authorized it yet".
--
-- CIRISAgent (CIRISAI/CIRISAgent#938) shipped `status = 'blocked'` plus an
-- agent-unwritable `__proposal__` metadata marker as the workaround. It
-- works — `blocked` is returned by neither discovery query — but `blocked`
-- means *work that is stuck* and a proposal is *work that is not
-- authorized*. Those are different operational states, and an operator
-- reading a blocked-ticket queue could not tell them apart.
--
-- The vocabulary stays CLOSED rather than becoming an open validated
-- string (the alternative the consumer offered). A closed set is what makes
-- an unknown status a refusal instead of a silently stored typo, and
-- authorization is exactly the kind of state that must not be expressible
-- by accident.
--
-- Nothing is removed and no row changes: the eight existing values remain
-- admissible with identical meaning, so every stored ticket is untouched
-- and this migration is safe to apply under load.
--
-- The `tickets_due_deadline` partial index is DELIBERATELY not modified.
-- Its predicate excludes the three TERMINAL states; `proposed` is not
-- terminal (it precedes the lifecycle rather than ending it), and a partial
-- index only gates planner eligibility, never result sets.
--
-- Dropped by DISCOVERY, not by name — the V114 lesson. V028 declares the
-- CHECK inline, so its name is whatever Postgres generated
-- (`tickets_status_check` on every database we have seen). Looking it up in
-- `pg_constraint` means a deployment whose constraint was ever renamed, or
-- restored from a dump under a different name, is migrated correctly rather
-- than silently left enforcing the 8-value set — which would make `proposed`
-- a runtime 23514 on exactly the deployments that took the trouble to rename
-- things. Matched on the COLUMN it constrains, which is stable.
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
      AND t.relname = 'tickets'
      AND c.contype = 'c'
      AND c.conkey = ARRAY[
            (SELECT a.attnum FROM pg_attribute a
              WHERE a.attrelid = t.oid AND a.attname = 'status')
          ]::smallint[];

    IF conname_to_drop IS NOT NULL THEN
        EXECUTE format(
            'ALTER TABLE cirislens.tickets DROP CONSTRAINT %I',
            conname_to_drop);
    END IF;
END
$$;

ALTER TABLE cirislens.tickets
    ADD CONSTRAINT tickets_status_check
    CHECK (status IN ('proposed', 'pending', 'assigned', 'in_progress',
                      'blocked', 'deferred', 'completed',
                      'cancelled', 'failed'));
