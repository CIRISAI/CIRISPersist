-- V177 — the blob row names the group it was sealed for, Postgres dialect
-- CIRISPersist#984 (rows 1 and 4)
--
-- SQLITE PARITY: migrations/sqlite/lens/V177__blob_group_key_id.sql
-- See that file's header for the rationale, including why nothing is
-- backfilled: NULL means unknown, and the retroactive-ADD listings exclude
-- an unknown group (an unknown family is not this family).

ALTER TABLE cirislens.federation_blobs
    ADD COLUMN group_key_id TEXT NULL;

COMMENT ON COLUMN cirislens.federation_blobs.group_key_id IS
    '#984 (rows 1 and 4) — the group the write named: the owner identity (self), the family key (family) or the community key, as the scoped doors received it. NULL = unknown (pre-V177, adopted, or a write that named no group). The retroactive-ADD walk joins on it and excludes NULL (fail-secure); durability resolves a family blob''s audience from it. Not backfilled: no pre-V177 row records its group.';
