-- V183 — the signed wire index, keyed by the record it names, Postgres dialect
-- v54.0.0 (CIRISPersist#995 row 5, Codex on PR #987)
--
-- SQLITE PARITY: migrations/sqlite/lens/V183__signed_wire_index_record_key.sql
-- See that file's header for the rationale.

CREATE INDEX IF NOT EXISTS signed_wire_index_record_key
    ON cirislens.signed_wire_index (kind, record_key);
