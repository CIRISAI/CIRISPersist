-- V065 — federation_stream_delivery_receipts subscriber acknowledgements,
-- Postgres dialect (CIRISPersist#142, Cut C4 — signed proof-of-delivery
-- for a stream chunk; CEG 0.15 §10.5.4).
--
-- Cut C4 closes the streaming loop: subscribers return signed
-- acknowledgements that they received chunk K under (stream_id, epoch).
-- A receipt is proof-of-DELIVERY, not proof-of-consumption — it commits
-- to having received bytes that commit to chunk K; it does NOT prove the
-- subscriber decrypted them (they may not hold the epoch DEK).
--
-- # The JOIN gate (why this is security-critical)
--
-- `put_delivery_receipt` is the integrity gate. Before a row lands here,
-- persist:
--   1. verifies the subscriber's hybrid signature over the receipt's
--      canonical signing bytes (receipt_signing_bytes; CEG §10.5.4),
--      with the subscriber's public key resolved from `federation_keys`
--      (NOT from bytes embedded in the signature); and
--   2. JOINs the receipt's `chunk_root` against a PUBLISHED STH for the
--      stream — a `federation_stream_sth` row (Cut C1b) whose `root_hash`
--      equals `chunk_root` at `tree_size >= k`. The signature is
--      necessary but NOT sufficient: a subscriber cannot acknowledge a
--      root the producer never published, nor a chunk index beyond the
--      published tree.
-- Only then is the row inserted.
--
-- Persist VALIDATES but does NOT ADJUDICATE: it composes no
-- "delivered"/"owes N" verdict and does NOT enforce community membership
-- — those are consumer policy (MISSION §1.4: validate origin + structure,
-- do not adjudicate meaning).
--
-- # Append-only / anti-equivocation
--
-- PRIMARY KEY (stream_id, subscriber_key_id, k): one receipt per
-- (stream, subscriber, chunk). A second receipt at the same key with a
-- DIFFERENT chunk_root is a subscriber equivocation attempt → rejected by
-- `put_delivery_receipt` (it reads the existing row's root and compares);
-- an identical re-PUT is idempotent. `epoch`/`k` are u64 in Rust → bound
-- i64 (BIGINT); tokio_postgres has no ToSql for u64.
--
-- # No CHECK-rebuild
--
-- NEW table — pure additive.

CREATE TABLE IF NOT EXISTS cirislens.federation_stream_delivery_receipts (
    -- The stream this receipt acknowledges. Joins to
    -- federation_stream_sth (the JOIN gate) and federation_stream_chunks.
    stream_id           TEXT NOT NULL,

    -- The acknowledging subscriber's federation_keys.key_id. The
    -- subscriber's public key is resolved from federation_keys via this
    -- id for the signature-verification gate.
    subscriber_key_id   TEXT NOT NULL,

    -- Key-rotation epoch the chunk was sealed under (per-epoch
    -- entitlement / billing scope; CEG §10.5.3). u64 in Rust → i64.
    epoch               BIGINT NOT NULL DEFAULT 0,

    -- Chunk index acknowledged (the K in §10.5.4). u64 in Rust → bound
    -- i64 (BIGINT). Part of the PK.
    k                   BIGINT NOT NULL,

    -- The committed STH root the subscriber saw at `tree_size >= k`. The
    -- put gate JOINs this against federation_stream_sth.root_hash for the
    -- stream; an unpublished root (or one only published at tree_size < k)
    -- is rejected. Exactly 32 bytes.
    chunk_root          BYTEA NOT NULL
        CHECK (octet_length(chunk_root) = 32),

    -- Serialized `ciris_crypto::HybridSignature` (Ed25519 + ML-DSA-65)
    -- over the receipt's canonical signing bytes. JSON-as-bytes,
    -- mirroring merkle_store's `serialize_signature` so PG and SQLite
    -- share the exact same encoding.
    signature_blob      BYTEA NOT NULL,

    -- Wall-clock persist accepted the receipt.
    received_at         TIMESTAMPTZ NOT NULL,

    -- One receipt per (stream, subscriber, chunk); append-only.
    PRIMARY KEY (stream_id, subscriber_key_id, k)
);

-- Serve list_delivery_receipts_for (all receipts for a stream, in chunk
-- order).
CREATE INDEX IF NOT EXISTS federation_stream_delivery_receipts_stream_k
    ON cirislens.federation_stream_delivery_receipts (stream_id, k);

COMMENT ON TABLE cirislens.federation_stream_delivery_receipts IS
    'v4.1 (CIRISPersist#142, Cut C4, CEG §10.5.4) — subscriber-signed proof-of-delivery for stream chunks. put_delivery_receipt verifies the subscriber''s hybrid signature against federation_keys, then JOINs the receipt''s chunk_root against a published federation_stream_sth row at tree_size >= k (the signature is necessary but NOT sufficient — a subscriber cannot acknowledge an unpublished root), then inserts. (stream_id, subscriber_key_id, k) PK = append-only; a same-key different-root receipt is a subscriber equivocation attempt and is rejected. Proof-of-delivery, not proof-of-consumption. Persist validates but does NOT adjudicate.';

COMMENT ON COLUMN cirislens.federation_stream_delivery_receipts.k IS
    'Chunk index acknowledged (K). u64 in Rust, bound i64 (BIGINT). Part of the PK. The put gate requires a published STH at tree_size >= k.';

COMMENT ON COLUMN cirislens.federation_stream_delivery_receipts.chunk_root IS
    'The STH root the subscriber acknowledges. JOINed against federation_stream_sth.root_hash (tree_size >= k) BEFORE insert; an unpublished root is rejected. 32 bytes.';

COMMENT ON COLUMN cirislens.federation_stream_delivery_receipts.signature_blob IS
    'Serialized ciris_crypto::HybridSignature (JSON-as-bytes) over receipt_signing_bytes; verified against the federation_keys row named by subscriber_key_id.';
