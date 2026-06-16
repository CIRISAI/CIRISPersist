-- V086 — §19.7 inter-object aggregation: the forever-memory pyramid
--        metadata (CEG 1.0-RC12 §19.7 / CIRISPersist#230, v8.3.0).
--
-- §19.7 reframes retirement as ONE pressure-driven monotonic fidelity
-- descent toward a NOISE FLOOR (the individual-recoverability boundary).
-- Operator 1 (intra-object fade) we already ship (V084 + tier eviction).
-- This migration adds the storage half of OPERATOR 2 (inter-object
-- aggregation): N source items → 1 composite, recursed into a mipmap
-- pyramid → O(log T) forever-memory. Each source's contribution sits
-- below the floor (individually unrecoverable); the collective blur (the
-- composite) persists forever — descent never terminates at zero.
--
-- persist is CODEC-FREE. The N→1 resampling compute is codec-side (edge);
-- persist stores + orchestrates. The composite IS a FountainContentV1
-- (corpus_kind = "aggregate:<source_corpus_kind>") admitted via the
-- EXISTING #225 hybrid-manifest gate (content_manifest / content_symbols,
-- V084). This table records ONLY the aggregation provenance.
--
-- THE WIRE-CHURN FIREWALL: the §19.7 aggregation wire shape is NOT yet
-- frozen (ratification in parallel — CIRISRegistry §19.7/#85, CIRISVerify
-- §19.7 verifiers ~v5.10.0, an edge ratification issue). So the §19.7 wire
-- payload is stored as OPAQUE BYTES (`aggregation_meta` BYTEA) that persist
-- NEVER parses; only the few navigation scalars persist itself needs are
-- promoted to typed columns. This keeps the immutable V086 robust to
-- whatever the §19.7 contract finalizes.
--
-- persist STORES `member_commitment` (the Merkle root over the folded
-- source content_ids) but does NOT verify it this cut — field-level /
-- byte-exact verification is §19.7-freeze-gated (CIRISVerify v5.10.0).
-- NO `verified` column (§19.0 F-5 — a verdict is recomputed at a gate,
-- never read from the wire; and there is no aggregation gate yet).
--
-- No TimescaleDB (operator directive; plain postgres:16): ordinary table
-- + ordinary index. No hypertable / CAGG / time_bucket / chunk policy.

CREATE TABLE IF NOT EXISTS cirislens.content_aggregation (
    -- The composite's FountainContentV1 content_id (one aggregation
    -- record per composite). corpus_kind of the composite is
    -- "aggregate:<source_corpus_kind>".
    aggregate_content_id  TEXT   NOT NULL,
    -- What was folded ("trace" | "blob" | "av_chunk" | "aggregate:..."
    -- for recursion).
    source_corpus_kind    TEXT   NOT NULL,
    -- Pyramid level: 0 = individual; level L folds N level-(L-1) items.
    aggregation_level     BIGINT NOT NULL,
    -- N — the N→1 fan-in ratio at this fold.
    fan_in                BIGINT NOT NULL,
    -- Merkle root (hex) over the folded source content_ids — proves
    -- membership WITHOUT storing N ids and WITHOUT individual
    -- recoverability. STORED, not verified this cut (§19.7-freeze-gated).
    member_commitment     TEXT   NOT NULL,
    -- OPAQUE §19.7 aggregation wire payload. persist NEVER parses this —
    -- stored byte-for-byte. The wire-churn firewall.
    aggregation_meta      BYTEA  NOT NULL,
    -- When persist recorded the fold (epoch ms).
    aggregated_at_unix_ms BIGINT NOT NULL,
    PRIMARY KEY (aggregate_content_id)
);

-- Pyramid navigation: walk a level newest-first for the O(log T)
-- forever-memory read.
CREATE INDEX IF NOT EXISTS content_aggregation_level_recency
    ON cirislens.content_aggregation (aggregation_level, aggregated_at_unix_ms);
