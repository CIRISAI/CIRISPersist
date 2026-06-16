-- V084 — fountain-coded content primitive (CIRISPersist#227).
--
-- The store-and-evict half of the `FountainContentV1` contract
-- (RATIFIED + LOCKED on CIRISPersist#227 / CIRISEdge#133). Persist is
-- store-and-evict-ONLY: zero codec crates, opaque symbol bytes,
-- reconstruction lives in the edge/consumer codec. This migration adds
-- the two at-rest tables; the admission gate (#225 hybrid verify on the
-- manifest), tier×priority eviction, and typed degraded-read live in
-- `src/fountain/`.
--
-- The envelope/payload split promoted to a substrate boundary:
--   * content_manifest — small, signed, ALWAYS retained, NEVER evicted.
--     One row per (content_id, corpus_kind). Carries the RaptorQ params
--     persist needs to know reconstruction thresholds (n_source,
--     k_repair, symbol_size, min_viable_symbols, original_content_length),
--     the ordered per-symbol SHA-256 hashes (so any surviving subset is
--     authenticated against the signed envelope), the corpus's own small
--     signed header (opaque to the store), and the producer HYBRID
--     signature (Ed25519 + ML-DSA-65; #225 hard cut — no classical-only).
--   * content_symbols — the N+K fountain symbols. Evictable. The rows
--     disk-pressure / consent-decay evict, highest retention_priority
--     first.
--
-- Versioning rule: V1 is frozen the moment this migration ships (shipped
-- migrations are immutable). Additive changes → FountainManifestV2 + a
-- new migration; the `manifest_version` column lets persist support
-- both. NEVER mutate V1.
--
-- No TimescaleDB (operator directive; V7.0.0 purge): plain postgres:16.
-- No hypertable / CAGG / time_bucket / chunk policy here — these are
-- ordinary tables with ordinary indexes.

CREATE TABLE IF NOT EXISTS cirislens.content_manifest (
    content_id              TEXT     NOT NULL,
    corpus_kind             TEXT     NOT NULL,
    manifest_version        INTEGER  NOT NULL,
    n_source                BIGINT   NOT NULL,
    k_repair                BIGINT   NOT NULL,
    symbol_size             BIGINT   NOT NULL,
    original_content_length BIGINT   NOT NULL,
    min_viable_symbols      BIGINT   NOT NULL,
    -- Ordered SHA-256 (hex) of every symbol; index == symbol_id,
    -- len == n_source + k_repair. JSON array of strings.
    symbol_hashes           JSONB    NOT NULL,
    -- The corpus's opaque signed header (for "trace" = the #225 hybrid
    -- trace envelope). Opaque to the store; bound by the signature.
    envelope                JSONB    NOT NULL,
    -- Producer HYBRID signature over canonical(content_id, corpus_kind,
    -- manifest_version, n_source, k_repair, symbol_size,
    -- original_content_length, min_viable_symbols, symbol_hashes,
    -- envelope). Both halves REQUIRED at admission (#225 hard cut).
    signature               TEXT     NOT NULL,  -- Ed25519 b64 (classical)
    signature_ml_dsa_65     TEXT     NOT NULL,  -- ML-DSA-65 b64 (REQUIRED)
    pqc_key_id              TEXT     NOT NULL,
    admitted_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (content_id, corpus_kind)
);

CREATE TABLE IF NOT EXISTS cirislens.content_symbols (
    content_id         TEXT     NOT NULL,
    symbol_id          BIGINT   NOT NULL,
    -- THE eviction key (a u8 on the wire). Lower = keep longest; persist
    -- evicts highest-priority-value first. One ORDER BY.
    retention_priority SMALLINT NOT NULL,
    -- Opaque fountain-symbol bytes. The codec/consumer reconstructs.
    symbol_bytes       BYTEA    NOT NULL,
    PRIMARY KEY (content_id, symbol_id)
);

-- Eviction ORDER BY support: highest retention_priority first within a
-- content_id (the single eviction key the contract names).
CREATE INDEX IF NOT EXISTS content_symbols_evict
    ON cirislens.content_symbols (content_id, retention_priority);
