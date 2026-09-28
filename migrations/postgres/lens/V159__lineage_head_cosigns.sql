-- V159 — lineage-head cosignatures: the witness plane of a conferring lineage
-- v51.0.0 (CIRISPersist#938 / #937, CC 3.2 T6 / T4a rc6, FSD TRUST_ROOT_RC6.md §1)
--
-- SQLITE PARITY: migrations/sqlite/lens/V159__lineage_head_cosigns.sql
-- (that file's header carries the reasoning; this one carries the DDL).
CREATE TABLE IF NOT EXISTS cirislens.federation_lineage_head_cosigns (
    lineage_key_id                TEXT NOT NULL,
    head_digest_sha256_hex        TEXT NOT NULL,
    witness_key_id                TEXT NOT NULL,
    head_asserted_at              TIMESTAMPTZ NOT NULL,
    prior_head_digest_sha256_hex  TEXT,
    signed_at                     TIMESTAMPTZ NOT NULL,
    signature_classical           TEXT NOT NULL,
    signature_pqc                 TEXT,
    admitted_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (lineage_key_id, head_digest_sha256_hex, witness_key_id)
);
CREATE INDEX IF NOT EXISTS idx_lineage_head_cosigns_lineage
    ON cirislens.federation_lineage_head_cosigns (lineage_key_id, signed_at);
