-- V148 (CIRISPersist#864, FSD/KEY_RECORD_REBIND.md §3) — the registration
-- claims a key row has REPLACED. A same-key rebind (the holder re-signs its
-- own unbound pre-#659 envelope so verify v15.2.0 peers admit it) rewrites
-- `federation_keys.registration_envelope` + signatures in place; the bytes it
-- replaced land here in the same transaction, oldest first, so the row's
-- history is auditable and a replayed old envelope is recognisable. No FK:
-- history outlives the key row. SQLite dialect. Postgres parity:
-- postgres/lens/V148.
CREATE TABLE federation_key_registration_history (
    history_id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id                     TEXT NOT NULL,
    registration_envelope      TEXT NOT NULL,
    original_content_hash      BLOB NOT NULL,
    scrub_signature_classical  TEXT NOT NULL,
    scrub_signature_pqc        TEXT,
    scrub_key_id               TEXT NOT NULL,
    scrub_timestamp            TEXT NOT NULL,   -- RFC-3339 UTC, the replaced record's own
    replaced_at                TEXT NOT NULL,   -- RFC-3339 UTC, THIS node's mutation instant
    replaced_by_hash           TEXT NOT NULL    -- persist_row_hash of the record that replaced it
);
CREATE INDEX federation_key_registration_history_by_key
    ON federation_key_registration_history (key_id, history_id);
