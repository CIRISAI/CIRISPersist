-- V131 — the receiver's position for a key row that MUTATES after arrival, PostgreSQL dialect
-- v36.0.0 (CIRISPersist#707)
--
-- SQLITE PARITY: migrations/sqlite/lens/V131__key_record_local_mutation_instant.sql
--
-- See the sqlite twin for the full reasoning. In short: five doors
-- (`adopt_scrub_upgrade`, `supersede_canonical_record`,
-- `adopt_genesis_reanchor`, `attach_key_pqc_signature`, `set_consent_role`)
-- rewrite consumer-visible `KeyRecord` bytes without moving any serve
-- position, so a consumer past the cursor never learned the row changed.
--
--     admitted_at — first admission, stable (V126, unchanged — its prose
--                   fixes that meaning, and re-stamping would destroy the
--                   only record of it).
--     mutated_at  — when THIS node last rewrote the row's consumer-visible
--                   bytes. Node-local, never on the wire, never in any
--                   content hash, NULL until a mutating door fires. Stamped
--                   through the same monotonic allocator.
--
-- The serve cursor keys on `GREATEST(admitted_at, mutated_at)` (GREATEST
-- ignores NULLs on this dialect, and `admitted_at` is NOT NULL here, so no
-- COALESCE is needed). `grant_trust` / `revoke_trust` write only `trust_*`
-- columns — outside `KeyRecord` — and deliberately do not stamp.
--
-- The allocator moves with the cursor: both read
-- `GREATEST(admitted_at, mutated_at)`, and the index below is on that same
-- expression. The V126 index keyed the expression the cursor no longer
-- reads — replaced, not accreted.

ALTER TABLE cirislens.federation_keys
    ADD COLUMN IF NOT EXISTS mutated_at TIMESTAMPTZ;

DROP INDEX IF EXISTS cirislens.federation_keys_admitted;

CREATE INDEX IF NOT EXISTS federation_keys_serve_position
    ON cirislens.federation_keys (GREATEST(admitted_at, mutated_at), key_id);
