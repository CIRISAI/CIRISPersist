-- V183 — the signed wire index, keyed by the record it names
-- v54.0.0 (CIRISPersist#995 row 5, Codex on PR #987)
--
-- POSTGRES PARITY: migrations/postgres/lens/V183__signed_wire_index_record_key.sql
--
-- `signed_wire_index` is keyed `(kind, content_hash)` (V111). When a record's
-- content hash moves (a withdrawn location proof, an anchor-scrub upgrade, a
-- PQC completion), the re-index upserts the NEW hash and the OLD
-- `(kind, old_hash)` row stayed behind, so `list_wire_hashes_since` kept
-- advertising a hash whose point read answers `None` and peers asked for it on
-- every anti-entropy pass. The upsert now deletes the record key's other
-- mappings in the same step; this index makes that delete a seek instead of a
-- scan of the whole index on every signed write.

CREATE INDEX IF NOT EXISTS signed_wire_index_record_key
    ON signed_wire_index (kind, record_key);
