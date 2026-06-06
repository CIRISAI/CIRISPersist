-- V062 — federation_stream_chunks live-stream chunk index, Postgres
-- dialect (CIRISPersist#142, Cut C1a — put_blob_chunk / seal_stream).
--
-- Cut C1a adds the LIVE-APPEND substrate on top of Cut B's content-
-- addressed chunk DAG. A producer appends chunks one at a time
-- (`put_blob_chunk(stream_id, seq, …)`) while the stream is live; each
-- chunk lands as a normal `federation_blobs` row (content-addressed by
-- its own SHA-256) AND a row in THIS table indexing it into the stream
-- at a monotonic `seq`. `seal_stream(stream_id)` later walks this index
-- in `seq` order and writes the Cut-B `chunk_dag` manifest row.
--
-- # Why a separate index table (vs. a column on federation_blobs)
--
-- `federation_blobs` is content-addressed (SHA-256 PK) and write-once;
-- the same chunk bytes might appear in two streams (or twice in one),
-- and a stream is an ORDERED sequence, not a set. The stream→(seq→sha)
-- mapping is therefore its own table. The blob row holds the bytes; this
-- table holds the position.
--
-- # Monotonicity guarantee
--
-- PRIMARY KEY (stream_id, seq). A re-used (stream_id, seq) is a PK
-- conflict → the INSERT fails → put_blob_chunk maps it to
-- BlobError::InvalidArgument. There is no UPSERT on the index row; the
-- monotonic seq is the substrate's append-only enforcement.
--
-- # Epoch column (stored now, no crypto this cut)
--
-- `epoch` is the key-rotation epoch the chunk was sealed under. Cut C1a
-- stores it but does NO key/crypto work (that is Cut C3 — the epoch-DEK
-- cascade). The (stream_id, epoch) index is here so the later
-- per-epoch walk (catch-up / re-key) is index-served from day one.
--
-- # No CHECK-rebuild
--
-- This is a NEW table — pure additive. (The non-additive RC1-1c
-- key_grant CHECK migration named in FSD §4.4 is a LATER cut; it is not
-- part of C1a.)

CREATE TABLE IF NOT EXISTS cirislens.federation_stream_chunks (
    -- The stream this chunk belongs to. Opaque producer-chosen id
    -- (CEG §10.5 log_id). Not an FK — streams are not first-class rows
    -- in this cut; the (stream_id, seq) pair is the only identity.
    stream_id   TEXT NOT NULL,

    -- Monotonic per-stream sequence number. Together with stream_id this
    -- is the PK, so a re-used seq is rejected at the driver (the
    -- monotonicity guarantee). u64 in Rust → bound as i64 (BIGINT);
    -- tokio_postgres has no ToSql for u64.
    seq         BIGINT NOT NULL,

    -- Content address of THIS chunk's bytes — a federation_blobs.sha256.
    -- Exactly 32 bytes. The bytes themselves live in the federation_blobs
    -- row keyed on this value (put_blob_chunk inserts both atomically).
    chunk_sha   BYTEA NOT NULL
        CHECK (octet_length(chunk_sha) = 32),

    -- Key-rotation epoch (CEG §10.5.3). Stored now; the DEK cascade is
    -- Cut C3. Defaults to 0 for callers that don't rotate.
    epoch       BIGINT NOT NULL DEFAULT 0,

    -- This chunk's byte length. Sum over the stream (seq order) is the
    -- sealed manifest's total_size.
    size_bytes  BIGINT NOT NULL CHECK (size_bytes >= 0),

    -- Wall-clock at append time.
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Set on seal_stream (informational — "when did this stream's index
    -- get frozen into a manifest"). NULL while the stream is live.
    sealed_at   TIMESTAMPTZ NULL,

    -- The monotonicity guarantee: a re-used (stream_id, seq) is a PK
    -- conflict. This index also serves the seq-ordered seal walk.
    PRIMARY KEY (stream_id, seq)
);

-- Per-(stream, epoch) index for the later epoch walk (catch-up /
-- re-key cascade, Cut C3). Cheap to add now; saves a rebuild later.
CREATE INDEX IF NOT EXISTS federation_stream_chunks_stream_epoch
    ON cirislens.federation_stream_chunks (stream_id, epoch);

COMMENT ON TABLE cirislens.federation_stream_chunks IS
    'v4.1 (CIRISPersist#142, Cut C1a) — live-stream chunk index. (stream_id, seq) PK is the monotonicity guarantee; chunk_sha references a federation_blobs row. put_blob_chunk appends; seal_stream walks seq-ordered to build the chunk_dag manifest. epoch stored for the Cut C3 DEK cascade (no crypto this cut).';

COMMENT ON COLUMN cirislens.federation_stream_chunks.seq IS
    'Monotonic per-stream sequence. Part of the PK — a re-used seq is rejected (append-only enforcement). u64 in Rust, bound i64.';

COMMENT ON COLUMN cirislens.federation_stream_chunks.epoch IS
    'Key-rotation epoch (CEG §10.5.3). Stored now; the epoch-DEK cascade is Cut C3 (no crypto this cut).';
