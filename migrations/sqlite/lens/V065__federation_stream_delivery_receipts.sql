-- V065 — federation_stream_delivery_receipts subscriber acknowledgements,
-- SQLite dialect (CIRISPersist#142, Cut C4 — signed proof-of-delivery for
-- a stream chunk; CEG 0.15 §10.5.4).
--
-- Mirrors postgres/lens/V065. NEW table — pure additive. See the PG
-- sibling for the full rationale. In brief: a delivery receipt is a
-- subscriber's hybrid-signed acknowledgement that they received chunk K
-- under (stream_id, epoch). Verification is a JOIN, not just a sig-check:
--   * the subscriber's hybrid signature over the canonical receipt bytes
--     is verified against federation_keys (necessary, NOT sufficient); and
--   * the receipt's chunk_root MUST be a real published STH root for the
--     stream (a federation_stream_sth row, C1b) at tree_size >= K — a
--     subscriber cannot acknowledge a root the producer never published.
-- Only then is the row inserted.
--
-- Persist VALIDATES (authenticates origin + JOINs against the published
-- root) but does NOT ADJUDICATE: no "delivered"/"owes N" verdict, no
-- community-membership enforcement (consumer policy; MISSION §1.4).
--
-- Type mapping vs. PG: BIGINT→INTEGER, BYTEA→BLOB, TIMESTAMPTZ→TEXT
-- (RFC3339). epoch/k are u64 in Rust → bound i64.

CREATE TABLE IF NOT EXISTS federation_stream_delivery_receipts (
    -- The stream this receipt acknowledges. Joins to
    -- federation_stream_sth / federation_stream_chunks.
    stream_id           TEXT NOT NULL,

    -- The acknowledging subscriber's federation_keys.key_id. The
    -- subscriber pubkey is resolved from federation_keys via this id
    -- for the signature gate.
    subscriber_key_id   TEXT NOT NULL,

    -- Key-rotation epoch the chunk was sealed under (per-epoch
    -- entitlement / billing scope). u64 in Rust, bound i64.
    epoch               INTEGER NOT NULL DEFAULT 0,

    -- Chunk index acknowledged (the K in §10.5.4). u64 in Rust, bound
    -- i64. Part of the PK.
    k                   INTEGER NOT NULL,

    -- The committed STH root the subscriber saw at tree_size >= k. The
    -- put gate JOINs this against federation_stream_sth.root_hash; an
    -- unpublished root is rejected. 32 B.
    chunk_root          BLOB NOT NULL
        CHECK (length(chunk_root) = 32),

    -- Serialized ciris_crypto::HybridSignature (Ed25519 + ML-DSA-65)
    -- over receipt_signing_bytes. JSON-as-bytes, same encoding PG/SQLite
    -- (mirror of merkle_store's serialize_signature).
    signature_blob      BLOB NOT NULL,

    -- Wall-clock persist accepted the receipt (RFC3339).
    received_at         TEXT NOT NULL,

    -- One receipt per (stream, subscriber, chunk); a re-PUT of the same
    -- (root) is idempotent, a different root at the same key is a
    -- subscriber equivocation attempt → rejected by put_delivery_receipt.
    PRIMARY KEY (stream_id, subscriber_key_id, k)
);

-- Serve list_delivery_receipts_for (all receipts for a stream, chunk
-- order).
CREATE INDEX IF NOT EXISTS federation_stream_delivery_receipts_stream_k
    ON federation_stream_delivery_receipts (stream_id, k);
