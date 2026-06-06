-- V062 — federation_stream_chunks live-stream chunk index, SQLite
-- dialect (CIRISPersist#142, Cut C1a — put_blob_chunk / seal_stream).
--
-- Mirrors postgres/lens/V062. NEW table — pure additive, no CHECK
-- rebuild (this is not the V054-style 12-step rebuild; nothing pre-
-- existing is touched). See the PG sibling for the full rationale:
--   * (stream_id, seq) PK = the monotonicity guarantee
--   * chunk_sha references a federation_blobs row (BLOB, 32 bytes)
--   * epoch stored now; the DEK cascade is Cut C3 (no crypto this cut)
--
-- Type mapping vs. PG: BIGINT→INTEGER, BYTEA→BLOB, TIMESTAMPTZ→TEXT
-- (RFC3339, like federation_blobs.first_seen_at / V047 SQLite).

CREATE TABLE IF NOT EXISTS federation_stream_chunks (
    -- Opaque producer-chosen stream id (CEG §10.5 log_id).
    stream_id   TEXT NOT NULL,

    -- Monotonic per-stream sequence. Part of the PK — a re-used seq is a
    -- PK conflict (the monotonicity guarantee). u64 in Rust, bound i64.
    seq         INTEGER NOT NULL,

    -- Content address of this chunk's bytes — a federation_blobs.sha256,
    -- exactly 32 bytes.
    chunk_sha   BLOB NOT NULL
        CHECK (length(chunk_sha) = 32),

    -- Key-rotation epoch (CEG §10.5.3). Stored now; cascade is Cut C3.
    epoch       INTEGER NOT NULL DEFAULT 0,

    -- This chunk's byte length.
    size_bytes  INTEGER NOT NULL CHECK (size_bytes >= 0),

    -- Wall-clock at append time (RFC3339).
    created_at  TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),

    -- Set on seal_stream (informational). NULL while live.
    sealed_at   TEXT NULL,

    -- The monotonicity guarantee + the seq-ordered seal walk index.
    PRIMARY KEY (stream_id, seq)
);

-- Per-(stream, epoch) index for the later epoch walk (Cut C3).
CREATE INDEX IF NOT EXISTS federation_stream_chunks_stream_epoch
    ON federation_stream_chunks (stream_id, epoch);
