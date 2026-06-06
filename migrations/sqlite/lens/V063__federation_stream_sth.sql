-- V063 — federation_stream_sth per-stream transparency log, SQLite
-- dialect (CIRISPersist#142, Cut C1b — producer-signed STH + RFC 6962
-- inclusion/consistency proofs over a stream's chunks; CEG 0.10
-- §10.5.1).
--
-- Mirrors postgres/lens/V063. NEW table — pure additive. See the PG
-- sibling for the full rationale:
--   * each live stream is its own RFC 6962 log; leaves are the chunk
--     hashes in federation_stream_chunks (NOT duplicated here)
--   * (stream_id, tree_size) PK = append-only / monotonic; a same-size
--     different-root STH is an equivocation attempt → rejected by
--     put_stream_sth
--   * put_stream_sth recomputes the root from persist's own chunks +
--     asserts equality (anti-equivocation gate), then verifies the
--     producer's hybrid signature against federation_keys, then inserts
--   * persist does NOT sign stream STHs (producer-signed best-effort
--     tier; no witness-cosign quorum enforcement this cut)
--
-- Type mapping vs. PG: BIGINT→INTEGER, BYTEA→BLOB, TIMESTAMPTZ→TEXT
-- (RFC3339), JSONB→TEXT. tree_size/epoch are u64 in Rust → bound i64.

CREATE TABLE IF NOT EXISTS federation_stream_sth (
    -- Parsed `<stream_id>` from the STH's `stream:<id>` log_id (CEG
    -- §10.5.1). Joins to federation_stream_chunks.
    stream_id           TEXT NOT NULL,

    -- RFC 6962 tree size (leaf/chunk count). u64 in Rust, bound i64.
    -- Part of the PK.
    tree_size           INTEGER NOT NULL,

    -- Key-rotation epoch (CEG §10.5.3). Stored now; cascade is Cut C3.
    epoch               INTEGER NOT NULL DEFAULT 0,

    -- Merkle root the STH claims. Recomputed from persist's own chunks
    -- and asserted equal BEFORE insert (anti-equivocation gate). 32 B.
    root_hash           BLOB NOT NULL
        CHECK (length(root_hash) = 32),

    -- Wall-clock the producer signed the STH (RFC3339).
    signed_at           TEXT NOT NULL,

    -- The federation_keys key that signed; the producer pubkey is
    -- resolved from federation_keys via this id for the sig gate.
    producer_key_id     TEXT NOT NULL,

    -- Serialized ciris_crypto::HybridSignature (JSON-as-bytes), mirror
    -- of merkle_store's serialize_signature (same encoding PG/SQLite).
    signature_blob      BLOB NOT NULL,

    -- Serialized witness cosignatures (CEG §10.5.1). Stored as-provided
    -- (default empty); no cosign quorum enforcement this cut.
    witness_signatures  TEXT NOT NULL DEFAULT '[]',

    -- One STH per (stream, size); append-only, monotonic tree_size.
    PRIMARY KEY (stream_id, tree_size)
);

-- Serve latest_stream_sth (highest tree_size for a stream).
CREATE INDEX IF NOT EXISTS federation_stream_sth_stream_size
    ON federation_stream_sth (stream_id, tree_size DESC);
