-- V085 — WholenessWitness corpus (CEG 1.0-RC11 §19.1; CIRISPersist#228
--        item 1 / #229 item 1).
--
-- persist is the §19 store + the WW-2 leaf-walk owner + the
-- divergence→§10.1.6 router. This migration adds the at-rest corpus that
-- holds the last-K VERIFIED witnesses per peer (K is a substrate const in
-- `src/witness/types.rs`; the store prunes to it). Every row in this
-- table is, by construction, a witness that ALREADY passed the
-- verify-before-persist hybrid-PQC gate (`src/witness/admit.rs`):
-- store-then-quarantine is non-conformant (N3 / RC8 / §10.1.5.1.1), so a
-- classical-only or invalid-ML-DSA-65 witness never reaches a row here.
--
-- § F-5 rule (verify at the gate, never trust an in-band flag): there is
-- NO `verified` column. A verdict is recomputed at ingest; a stored row
-- is a verified row.
--
-- The witness's signed scalars mirror
-- `ciris_verify_core::holonomic::WholenessWitness`; the bound-hybrid
-- signature halves (Ed25519 + ML-DSA-65, both REQUIRED — §19.0
-- PQC-mandatory) + the producer ML-DSA-65 key id ride along so persist can
-- RE-verify / re-compare on read. claim_namespaces is the WW-2-filtered
-- namespace set (NEVER names anonymous/self — enforced at the gate).
--
-- §19 objects sign a binary length-prefixed BE domain-separated preimage
-- (NOT JCS — the framing lives in verify-core); the merkle_root is stored
-- as lowercase hex (64 chars). NO TimescaleDB (operator directive): plain
-- postgres:16, ordinary table + index — no hypertable / CAGG / time_bucket
-- / chunk policy.

CREATE TABLE IF NOT EXISTS cirislens.wholeness_witness_corpus (
    peer_id             TEXT     NOT NULL,
    -- Per-peer monotonic epoch (anti-rollback / eclipse guard, N4).
    epoch_id            BIGINT   NOT NULL,
    observed_at_unix_ms BIGINT   NOT NULL,
    -- WW-2-filtered namespace set (JSON array of strings; NEVER names
    -- anonymous/self — gate-enforced).
    claim_namespaces    JSONB    NOT NULL,
    -- §19.1 Merkle root over the WW-2-filtered, lexicographically ordered
    -- leaves — lowercase hex (64 chars).
    merkle_root         TEXT     NOT NULL,
    leaf_count          BIGINT   NOT NULL,
    witness_version     INTEGER  NOT NULL,
    -- Bound-hybrid signature halves over the §19.1 canonical preimage.
    -- Both REQUIRED at the gate (§19.0 PQC-mandatory; no classical-only).
    signature           TEXT     NOT NULL,  -- Ed25519 b64 (classical)
    signature_ml_dsa_65 TEXT     NOT NULL,  -- ML-DSA-65 b64 (REQUIRED)
    pqc_key_id          TEXT     NOT NULL,
    admitted_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- One row per (peer, epoch, observation instant). A re-observation at
    -- the same instant is idempotent; a genuine new epoch/instant is a
    -- distinct row (and the equivocation classifier compares roots).
    PRIMARY KEY (peer_id, epoch_id, observed_at_unix_ms)
);

-- last-K-per-peer prune support + the comparison fetch (newest first
-- within a peer).
CREATE INDEX IF NOT EXISTS wholeness_witness_corpus_peer_recency
    ON cirislens.wholeness_witness_corpus (peer_id, observed_at_unix_ms DESC);
