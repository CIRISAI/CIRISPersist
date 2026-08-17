-- V131 — the receiver's position for a key row that MUTATES after arrival, SQLite dialect
-- v36.0.0 (CIRISPersist#707)
--
-- POSTGRES PARITY: migrations/postgres/lens/V131__key_record_local_mutation_instant.sql
--
-- WHAT AND WHY
-- ------------
-- #682 (V126) fixed the row that ARRIVES late: `admitted_at`, this node's own
-- admission position, keys the serve cursor. It did not touch the row that
-- MUTATES after arrival. Five production doors UPDATE `federation_keys` and
-- rewrite bytes a consumer receives through `list_signed_key_records_since` —
--
--     adopt_scrub_upgrade, supersede_canonical_record, adopt_genesis_reanchor,
--     attach_key_pqc_signature, set_consent_role
--
-- — and none of them moved any serve position. A consumer whose cursor had
-- passed the row NEVER learned it changed. `adopt_scrub_upgrade` is the
-- sharpest instance: its entire purpose is to re-root a key to the accord
-- anchor, and a peer past the cursor kept the pre-anchor row forever. The
-- wire index DOES follow these doors (#547), so a peer that already knows the
-- new content hash can fetch the row — but the cursor is how a peer learns a
-- hash exists, and the cursor could not see the mutation.
--
-- WHY A SECOND COLUMN, NOT A RE-STAMP OF admitted_at
-- --------------------------------------------------
-- V126's own prose fixes `admitted_at` as "when THIS node admitted the row".
-- Re-stamping it on mutation would silently change that to "when this node
-- last touched the row", and "how long have we held this key" — a plausible
-- input to trust and age reasoning — would stop being answerable. Both facts
-- are kept:
--
--     admitted_at — first admission, stable (V126, unchanged).
--     mutated_at  — when THIS node last rewrote the row's consumer-visible
--                   bytes. Node-local, never on the wire, never in any
--                   content hash, NULL until a mutating door fires.
--                   Stamped through the same monotonic allocator as
--                   admitted_at.
--
-- The serve cursor keys on the greater of the two — the established idiom on
-- the accord evidence plane (`MAX(created_at, MAX(server_arrival_at))`), which
-- V123 cites as the precedent for `admitted_at` itself. Moving a row FORWARD
-- in a stream read ascending and filtered `> cursor` can never strand it:
-- ahead of the cursor it is seen at its new position; behind, it is seen
-- AGAIN — a duplicate, the safe direction for an idempotent replication
-- consumer.
--
-- `grant_trust` / `revoke_trust` also UPDATE this table but write only
-- `trust_*` columns, none of which are `KeyRecord` fields — no peer ever
-- received them, so no peer's copy can go stale. They deliberately do NOT
-- stamp `mutated_at`: re-stamping on every UPDATE would churn the stream for
-- changes no peer can observe.
--
-- THE ALLOCATOR MUST MOVE WITH THE CURSOR (#682's invariant: the allocator
-- reads the expression the reader reads). The serve-position expression on
-- this dialect, spelled ONCE and matched exactly by the cursor, the
-- allocator, and the index below:
--
--     MAX(COALESCE(admitted_at, scrub_timestamp),
--         COALESCE(mutated_at, COALESCE(admitted_at, scrub_timestamp)))
--
-- (SQLite's scalar MAX returns NULL if ANY argument is NULL, so `mutated_at`
-- is COALESCEd to the admission expression rather than compared bare. RFC-3339
-- UTC text orders lexicographically the same way it orders in time.)
--
-- The V126 index was on the admission expression alone; the cursor no longer
-- reads that expression, so the index follows the reader — replaced, not
-- accreted.

ALTER TABLE federation_keys ADD COLUMN mutated_at TEXT;

DROP INDEX IF EXISTS federation_keys_admitted;

CREATE INDEX IF NOT EXISTS federation_keys_serve_position
    ON federation_keys (
        MAX(COALESCE(admitted_at, scrub_timestamp),
            COALESCE(mutated_at, COALESCE(admitted_at, scrub_timestamp))),
        key_id
    );
