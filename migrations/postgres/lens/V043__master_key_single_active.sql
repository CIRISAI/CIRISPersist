-- V043 — DB-enforced "exactly one active master key" invariant.
-- (2.0, CIRISPersist secrets-substrate concurrency hardening.)
--
-- # The bug this closes
--
-- `rotate_master_key` first-use activation was a check-then-act:
-- INSERT the new key row, then (separately) COUNT active keys and
-- conditionally UPDATE activated_at. Nothing in the schema forbade
-- two rows being active at once. On Postgres (real pool → true
-- parallelism) two concurrent first-use rotations both saw COUNT=0
-- and both activated → `active_master_key()` then errored
-- ("N active master keys; expected exactly 1") and `encrypt()`
-- failed. The CIRIS 3.0 cohabitation model (one shared engine handed
-- to multiple co-resident Rust consumers) makes concurrent secrets
-- bootstrap a live path.
--
-- # The "active" predicate
--
-- `active_master_key()` selects the operative master key. The
-- operative key is one that has been ACTIVATED and not since
-- RETIRED — i.e. `activated_at IS NOT NULL AND deactivated_at IS
-- NULL`. A row with `activated_at IS NULL` is a *staged* key
-- (rotate_master_key / migrate_to_hardware_key inserted it; it is
-- not yet operative). 2.0 reconciles `active_master_key()`,
-- `rotate_master_key`'s COUNT, and this index on that one
-- definition.
--
-- # The index
--
-- A UNIQUE index over a constant expression (TRUE), partial to the
-- active predicate: at most one row can satisfy the predicate, so
-- the DB itself caps active master keys at one. A concurrent
-- first-use rotation that loses the race hits this on its activating
-- UPDATE's commit; `rotate_master_key` catches the unique violation,
-- re-reads, and returns the winner's key.

BEGIN;

CREATE UNIQUE INDEX IF NOT EXISTS master_key_one_active
    ON cirislens_secrets.master_key_meta ((TRUE))
    WHERE activated_at IS NOT NULL AND deactivated_at IS NULL;

COMMENT ON INDEX cirislens_secrets.master_key_one_active IS
    'v2.0 (CIRISPersist secrets-concurrency hardening) — DB-enforced "exactly one active master key". active := activated_at IS NOT NULL AND deactivated_at IS NULL. Backstops rotate_master_key''s first-use activation against concurrent bootstrap.';

COMMIT;
