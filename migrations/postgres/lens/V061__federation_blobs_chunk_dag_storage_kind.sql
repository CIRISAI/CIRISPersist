-- V061 — admit 'chunk_dag' into federation_blobs.storage_kind, Postgres
-- dialect (CIRISPersist#142, Cut B — BlobBody::ChunkDag).
--
-- Cut B adds a fourth storage_kind: 'chunk_dag'. The manifest (a
-- JCS-canonical chunk list) is stored in `bytes_inline` exactly like an
-- 'inline' body, and `external_ref` is NULL. V047 carries two CHECKs
-- that close the door on this value:
--
--   * federation_blobs_storage_kind_check
--       CHECK (storage_kind IN ('inline','s3','external_url'))
--   * federation_blobs_storage_kind_columns_match
--       CHECK ( (inline → bytes_inline present, external_ref NULL)
--               OR (s3/external_url → bytes_inline NULL, external_ref present) )
--
-- Postgres supports in-place constraint swap (DROP + ADD), so this is
-- the bounded half. Both CHECKs are dropped and re-added with the
-- 'chunk_dag' arm. The chunk_dag arm mirrors the 'inline' body shape:
-- bytes_inline IS NOT NULL AND external_ref IS NULL.
--
-- The SQLite sibling (sqlite/lens/V061) does the 12-step table rebuild
-- because table-level CHECKs can't be ALTERed there.

-- 1. storage_kind enum CHECK — admit 'chunk_dag'.
ALTER TABLE cirislens.federation_blobs
    DROP CONSTRAINT federation_blobs_storage_kind_check;

ALTER TABLE cirislens.federation_blobs
    ADD CONSTRAINT federation_blobs_storage_kind_check
        CHECK (storage_kind IN ('inline', 's3', 'external_url', 'chunk_dag'));

-- 2. Cross-column CHECK — add the chunk_dag arm (manifest in
--    bytes_inline, like inline; external_ref NULL).
ALTER TABLE cirislens.federation_blobs
    DROP CONSTRAINT federation_blobs_storage_kind_columns_match;

ALTER TABLE cirislens.federation_blobs
    ADD CONSTRAINT federation_blobs_storage_kind_columns_match
        CHECK (
            (storage_kind = 'inline'
                AND bytes_inline IS NOT NULL
                AND external_ref IS NULL)
            OR
            (storage_kind = 'chunk_dag'
                AND bytes_inline IS NOT NULL
                AND external_ref IS NULL)
            OR
            (storage_kind IN ('s3', 'external_url')
                AND bytes_inline IS NULL
                AND external_ref IS NOT NULL)
        );

COMMENT ON COLUMN cirislens.federation_blobs.storage_kind IS
    'How the bytes are stored: inline (bytes_inline) | s3 (external_ref) | external_url (external_ref) | chunk_dag (JCS manifest in bytes_inline; CIRISPersist#142 Cut B). First-write-wins on conflict — see put_blob doc.';
