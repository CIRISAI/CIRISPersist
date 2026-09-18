-- V148 (CIRISPersist#864, FSD/KEY_RECORD_REBIND.md §3) — the registration
-- claims a key row has REPLACED. A same-key rebind (the holder re-signs its
-- own unbound pre-#659 envelope so verify v15.2.0 peers admit it) rewrites
-- `federation_keys.registration_envelope` + signatures in place; the bytes it
-- replaced land here in the same transaction, oldest first, so the row's
-- history is auditable and a replayed old envelope is recognisable. No FK:
-- history outlives the key row. Postgres dialect. SQLite parity:
-- sqlite/lens/V148.
CREATE TABLE cirislens.federation_key_registration_history (
    history_id                 BIGSERIAL PRIMARY KEY,
    key_id                     TEXT NOT NULL,
    registration_envelope      TEXT NOT NULL,
    original_content_hash      BYTEA NOT NULL,
    scrub_signature_classical  TEXT NOT NULL,
    scrub_signature_pqc        TEXT,
    scrub_key_id               TEXT NOT NULL,
    scrub_timestamp            TIMESTAMPTZ NOT NULL,   -- the replaced record's own
    replaced_at                TIMESTAMPTZ NOT NULL,   -- THIS node's mutation instant
    replaced_by_hash           TEXT NOT NULL           -- persist_row_hash of the record that replaced it
);
CREATE INDEX federation_key_registration_history_by_key
    ON cirislens.federation_key_registration_history (key_id, history_id);
