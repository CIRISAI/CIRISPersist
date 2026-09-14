-- V144 — author is not holder, Postgres dialect
-- CIRISPersist#846 (FSD/BLOB_REPLICATION.md §5, I49)
--
-- SQLITE PARITY: migrations/sqlite/lens/V144__blob_author_key_id.sql
-- See that file's header for the rationale, including why nothing is
-- backfilled: NULL means unknown, and unknown classifies as proxy.

ALTER TABLE cirislens.federation_blobs
    ADD COLUMN author_key_id TEXT NULL;

COMMENT ON COLUMN cirislens.federation_blobs.author_key_id IS
    '#846 (BLOB_REPLICATION.md §5) — the attesting_key_id of the attestation this blob is a projection of: the writer''s DERIVED federation key id for a local write (I23), the declared provenance for an adopted one. NULL = unknown, which is_proxy_content treats as proxy (fail toward evictable). Not backfilled: no pre-V144 row records its author.';
