-- V043 — DB-enforced "exactly one active master key" invariant.
-- (2.0, CIRISPersist secrets-substrate concurrency hardening.)
--
-- SQLite mirror of migrations/postgres/lens/V043. The SQLite single
-- connection-mutex masked the concurrent-bootstrap race, but the
-- invariant must hold on both backends (parity); a partial UNIQUE
-- index makes "more than one active master key" unrepresentable
-- regardless of backend.
--
-- # The "active" predicate
--
-- active := activated_at IS NOT NULL AND deactivated_at IS NULL.
-- A row with activated_at IS NULL is a *staged* key (inserted by
-- rotate_master_key / migrate_to_hardware_key, not yet operative).
-- `active_master_key()`, `rotate_master_key`'s COUNT, and this index
-- all agree on that one definition.
--
-- # The index
--
-- A UNIQUE index over a constant expression (1), partial to the
-- active predicate: at most one row can satisfy it, so the DB caps
-- active master keys at one.

CREATE UNIQUE INDEX IF NOT EXISTS master_key_one_active
    ON cirislens_secrets_master_key_meta (1)
    WHERE activated_at IS NOT NULL AND deactivated_at IS NULL;
