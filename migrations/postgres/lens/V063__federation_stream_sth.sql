-- V063 — federation_stream_sth per-stream transparency log, Postgres
-- dialect (CIRISPersist#142, Cut C1b — producer-signed STH + RFC 6962
-- inclusion/consistency proofs over a stream's chunks; CEG 0.10
-- §10.5.1).
--
-- Cut C1b makes each live stream (Cut C1a) its OWN RFC 6962
-- transparency log. The log's `log_id` is `stream:<stream_id>`; its
-- LEAVES are the chunk hashes already stored in
-- `federation_stream_chunks` (Cut C1a) — this table does NOT duplicate
-- leaf storage. What it stores is the **Signed Tree Head**: a
-- producer-signed snapshot of the log at a given `tree_size`.
--
-- # The anti-equivocation gate (why this is security-critical)
--
-- `put_stream_sth` is the integrity gate. Before a row lands here,
-- persist:
--   1. recomputes the Merkle root from ITS OWN stored chunks
--      (federation_stream_chunks, seq ASC, first `tree_size` of them)
--      via the CIRISVerify RFC 6962 store, and asserts it equals the
--      STH's claimed `root_hash` — a producer cannot register a root
--      inconsistent with the chunks persist holds; and
--   2. verifies the producer's hybrid signature over the STH's
--      canonical signing bytes, with the producer's public key resolved
--      from `federation_keys` (NOT from the bytes embedded in the
--      signature).
-- Only then is the row inserted. Persist does NOT sign stream STHs
-- (unlike the audit log's `merkle_sth_log`) — the producer signs; this
-- is the best-effort tier (CEG §10.5.1: producer-signed only, no
-- witness-cosign quorum enforcement THIS cut).
--
-- # Append-only / monotonic
--
-- PRIMARY KEY (stream_id, tree_size): one STH per (stream, size). A
-- second STH at the same (stream_id, tree_size) with a DIFFERENT root
-- is an equivocation attempt → rejected by `put_stream_sth` (it reads
-- the existing row's root and compares); an identical re-PUT is
-- idempotent. `tree_size` is u64 in Rust → bound as i64 (BIGINT);
-- tokio_postgres has no ToSql for u64.
--
-- # No CHECK-rebuild
--
-- NEW table — pure additive.

CREATE TABLE IF NOT EXISTS cirislens.federation_stream_sth (
    -- The stream this STH describes. The log_id baked into the STH is
    -- `stream:<stream_id>` (CEG §10.5.1 log_id); this column is the
    -- parsed `<stream_id>` and joins to federation_stream_chunks.
    stream_id           TEXT NOT NULL,

    -- Number of leaves (chunks) the STH covers — the RFC 6962 tree
    -- size. u64 in Rust → bound i64 (BIGINT). Part of the PK.
    tree_size           BIGINT NOT NULL,

    -- Key-rotation epoch (CEG §10.5.3). Stored now; no crypto cascade
    -- this cut (that is Cut C3). u64 in Rust → bound i64.
    epoch               BIGINT NOT NULL DEFAULT 0,

    -- The Merkle root the STH claims for `tree_size` leaves. Persist
    -- recomputes this from its own chunks and asserts equality BEFORE
    -- insert (the anti-equivocation gate). Exactly 32 bytes.
    root_hash           BYTEA NOT NULL
        CHECK (octet_length(root_hash) = 32),

    -- Wall-clock the producer signed the STH (the STH's `timestamp`,
    -- part of the signed canonical bytes).
    signed_at           TIMESTAMPTZ NOT NULL,

    -- The federation_keys key that signed this STH. The producer's
    -- public key is resolved from federation_keys via this id for the
    -- signature-verification gate.
    producer_key_id     TEXT NOT NULL,

    -- Serialized `ciris_crypto::HybridSignature` (Ed25519 + ML-DSA-65)
    -- over the STH's canonical signing bytes. JSON-as-bytes, mirroring
    -- merkle_store's `serialize_signature` so PG and SQLite share the
    -- exact same encoding.
    signature_blob      BYTEA NOT NULL,

    -- Serialized witness cosignatures (CEG §10.5.1). Stored as-provided
    -- (default empty) — Cut C1b does NOT enforce a cosign quorum
    -- (best-effort tier = producer-signed only). Mirrors merkle_store's
    -- witness serialization. JSONB so the column is queryable later.
    witness_signatures  JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- One STH per (stream, size); append-only, monotonic tree_size.
    PRIMARY KEY (stream_id, tree_size)
);

-- Serve the `latest_stream_sth` query (highest tree_size for a stream).
CREATE INDEX IF NOT EXISTS federation_stream_sth_stream_size
    ON cirislens.federation_stream_sth (stream_id, tree_size DESC);

COMMENT ON TABLE cirislens.federation_stream_sth IS
    'v4.1 (CIRISPersist#142, Cut C1b, CEG §10.5.1) — per-stream transparency log: producer-signed Signed Tree Heads over a stream''s chunk hashes (leaves live in federation_stream_chunks). put_stream_sth recomputes the root from persist''s own chunks + asserts equality with the claimed root (anti-equivocation gate), then verifies the producer''s hybrid signature against federation_keys, then inserts. (stream_id, tree_size) PK = append-only/monotonic; a same-size different-root STH is an equivocation attempt and is rejected. Persist does NOT sign stream STHs.';

COMMENT ON COLUMN cirislens.federation_stream_sth.tree_size IS
    'RFC 6962 tree size (leaf count). u64 in Rust, bound i64 (BIGINT). Part of the PK.';

COMMENT ON COLUMN cirislens.federation_stream_sth.root_hash IS
    'Merkle root the STH claims. Recomputed from federation_stream_chunks and asserted equal BEFORE insert (anti-equivocation gate). 32 bytes.';

COMMENT ON COLUMN cirislens.federation_stream_sth.signature_blob IS
    'Serialized ciris_crypto::HybridSignature (JSON-as-bytes) over the STH signing bytes; verified against the federation_keys row named by producer_key_id.';
