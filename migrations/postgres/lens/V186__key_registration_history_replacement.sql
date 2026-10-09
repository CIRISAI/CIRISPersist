-- V186 (CIRISPersist#1044) — what a key-registration history row replaced,
-- and which door replaced it. Postgres dialect. SQLite parity:
-- sqlite/lens/V186.
--
-- V148's history row named the record that REPLACED it (`replaced_by_hash`)
-- but not the row it audits. v54.1.0 adds a second replacement door: a stored
-- key record that fails `verify_key_registration` is replaced by an incoming
-- record with the same pubkeys and claim that passes (`invalid_replaced`).
-- Both doors write the replaced row's own `persist_row_hash` and their kind.
-- Rows written before V186 were all rebinds (the only door then); their
-- replaced hash was never recorded and stays NULL.
ALTER TABLE cirislens.federation_key_registration_history
    ADD COLUMN IF NOT EXISTS replaced_row_hash TEXT;
ALTER TABLE cirislens.federation_key_registration_history
    ADD COLUMN IF NOT EXISTS replacement_kind TEXT NOT NULL DEFAULT 'rebind'
        CHECK (replacement_kind IN ('rebind', 'invalid_replaced'));
