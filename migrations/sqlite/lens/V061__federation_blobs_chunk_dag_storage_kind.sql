-- V061 — admit 'chunk_dag' into federation_blobs.storage_kind, SQLite
-- dialect (CIRISPersist#142, Cut B — BlobBody::ChunkDag).
--
-- Mirrors postgres/lens/V061. Cut B adds a fourth storage_kind:
-- 'chunk_dag' (the JCS manifest lives in `bytes_inline`, like 'inline').
-- V047 baked TWO table-level CHECKs into CREATE TABLE:
--   * the storage_kind enum     CHECK (storage_kind IN (...))
--   * the cross-column rule      CHECK (inline → bytes_inline / s3,url → external_ref)
--
-- SQLite CANNOT `ALTER TABLE ... DROP CONSTRAINT` table-level CHECKs —
-- they're part of the CREATE TABLE statement. So this is the standard
-- 12-step table rebuild (mirrors V035 / V020):
--
--   1. PRAGMA defer_foreign_keys = ON
--   2. CREATE TABLE federation_blobs_new with the extended CHECKs +
--      ALL columns (incl. the V053 access-tracking columns
--      last_accessed_at / access_count)
--   3. INSERT INTO new (cols...) SELECT cols... FROM old  (preserve data)
--   4. DROP TABLE old
--   5. ALTER TABLE new RENAME TO federation_blobs
--   6. Recreate ALL THREE indexes (V047 size_bytes + first_seen_at,
--      V053 eviction_score)
--
-- No triggers exist on federation_blobs (verified: only V047 + V053
-- touch it), so none to recreate. Refinery wraps each migration in its
-- own transaction; defer_foreign_keys resets at COMMIT.

PRAGMA defer_foreign_keys = ON;

CREATE TABLE federation_blobs_new (
    -- SHA-256 content hash (32 bytes raw).
    sha256        BLOB PRIMARY KEY
        CHECK (length(sha256) = 32),

    -- 'inline' | 's3' | 'external_url' | 'chunk_dag'  (V061 adds chunk_dag).
    storage_kind  TEXT NOT NULL
        CHECK (storage_kind IN ('inline', 's3', 'external_url', 'chunk_dag')),

    -- Inline body OR (V061) the JCS chunk-DAG manifest. Present iff
    -- storage_kind in ('inline','chunk_dag').
    bytes_inline  BLOB,

    -- External URI/URL. Present iff storage_kind in ('s3','external_url').
    external_ref  TEXT,

    size_bytes    INTEGER NOT NULL CHECK (size_bytes >= 0),

    media_type    TEXT,

    first_seen_at TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),

    -- JSON array string. Empty array = no region-specific tracking.
    regions_held  TEXT NOT NULL DEFAULT '[]',

    -- V053 access-tracking columns (MUST survive the rebuild).
    last_accessed_at TEXT NOT NULL
        DEFAULT '1970-01-01T00:00:00+00:00',
    access_count  INTEGER NOT NULL DEFAULT 0,

    -- Cross-column rule, extended with the chunk_dag arm (manifest in
    -- bytes_inline, like inline; external_ref NULL).
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
    )
);

-- Preserve every existing row (column list is explicit so a future
-- column-order drift can't silently misalign the copy).
INSERT INTO federation_blobs_new (
    sha256,
    storage_kind,
    bytes_inline,
    external_ref,
    size_bytes,
    media_type,
    first_seen_at,
    regions_held,
    last_accessed_at,
    access_count
)
SELECT
    sha256,
    storage_kind,
    bytes_inline,
    external_ref,
    size_bytes,
    media_type,
    first_seen_at,
    regions_held,
    last_accessed_at,
    access_count
FROM federation_blobs;

DROP TABLE federation_blobs;

ALTER TABLE federation_blobs_new RENAME TO federation_blobs;

-- Recreate ALL indexes (V047 + V053).
CREATE INDEX IF NOT EXISTS federation_blobs_size_bytes
    ON federation_blobs (size_bytes);

CREATE INDEX IF NOT EXISTS federation_blobs_first_seen_at
    ON federation_blobs (first_seen_at DESC);

CREATE INDEX IF NOT EXISTS federation_blobs_eviction_score
    ON federation_blobs (last_accessed_at ASC, access_count ASC);
