-- V047 — Content-addressable federation_blobs storage, SQLite dialect
-- (CIRISPersist#103).
--
-- Postgres parity (postgres/lens/V047): same table shape with the
-- following dialect translations:
--
--   PostgreSQL                       → SQLite
--   ─────────────────────────────────────────────────────────────────
--   BYTEA                            → BLOB
--   TIMESTAMPTZ NOT NULL DEFAULT NOW() → TEXT NOT NULL DEFAULT
--                                       (datetime('now', 'subsec'))
--   TEXT[] DEFAULT '{}'              → TEXT NOT NULL DEFAULT '[]'
--                                       (JSON array string)
--   octet_length(bytea)              → length(blob) (SQLite length()
--                                       on BLOB returns bytes)
--
-- The storage_kind ↔ body-column asymmetry is enforced by an inline
-- table-level CHECK (the same shape as the PG named constraint) —
-- SQLite supports inline CHECKs at table creation time, so we don't
-- need triggers like V046 did.
--
-- See postgres/lens/V047 for the architectural rationale.

CREATE TABLE IF NOT EXISTS federation_blobs (
    -- SHA-256 content hash (32 bytes raw).
    sha256        BLOB PRIMARY KEY
        CHECK (length(sha256) = 32),

    -- 'inline' | 's3' | 'external_url'.
    storage_kind  TEXT NOT NULL
        CHECK (storage_kind IN ('inline', 's3', 'external_url')),

    -- Inline body. Present iff storage_kind='inline'.
    bytes_inline  BLOB,

    -- External URI/URL. Present iff storage_kind in ('s3','external_url').
    external_ref  TEXT,

    size_bytes    INTEGER NOT NULL CHECK (size_bytes >= 0),

    media_type    TEXT,

    first_seen_at TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),

    -- JSON array string. Empty array = no region-specific tracking.
    regions_held  TEXT NOT NULL DEFAULT '[]',

    -- Defense in depth — see PG V047. Inline CHECK works on SQLite
    -- (no need for the trigger pattern V046 had for cross-table
    -- ALTER constraints).
    CHECK (
        (storage_kind = 'inline'
            AND bytes_inline IS NOT NULL
            AND external_ref IS NULL)
        OR
        (storage_kind IN ('s3', 'external_url')
            AND bytes_inline IS NULL
            AND external_ref IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS federation_blobs_size_bytes
    ON federation_blobs (size_bytes);

CREATE INDEX IF NOT EXISTS federation_blobs_first_seen_at
    ON federation_blobs (first_seen_at DESC);
