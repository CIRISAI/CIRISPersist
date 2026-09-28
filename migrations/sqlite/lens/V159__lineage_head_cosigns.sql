-- V159 — lineage-head cosignatures: the witness plane of a conferring lineage
-- v51.0.0 (CIRISPersist#938 / #937, CC 3.2 T6 / T4a rc6, FSD TRUST_ROOT_RC6.md §1)
--
-- POSTGRES PARITY: migrations/postgres/lens/V159__lineage_head_cosigns.sql
--
-- # Why
--
-- A family or `infrastructure` community whose members confer standing is a
-- WITNESSED lineage (CC 3.2 T6): every head of its roster chain is committed
-- to the CC 5.3.1 witness plane as a lineage-head cosignature by an
-- independent witness (`identity_type ⊇ {witness}`, never a founder of the
-- lineage). The fold adopts only witnessed heads; two witnessed heads for one
-- lineage are equivocation, and the cosignatures ARE the evidence. Attaching
-- a root (T4a) needs a witnessed head inside the charter's attach window.
--
-- # What this stores
--
-- One row per (lineage, head, witness): the object `ciris.lineage_head_cosign.v1`
-- exactly as admitted — the witness's signer-stamped `signed_at`, the head's
-- signer-stamped `head_asserted_at`, the prior head this witness last cosigned
-- (absent on its first), and the hybrid signatures. `admitted_at` is node-local
-- and is read by no verdict. Nothing here is ever deleted: a cosign that names
-- a competing head is the equivocation evidence.
CREATE TABLE IF NOT EXISTS federation_lineage_head_cosigns (
    lineage_key_id                TEXT NOT NULL,
    head_digest_sha256_hex        TEXT NOT NULL,
    witness_key_id                TEXT NOT NULL,
    head_asserted_at              TEXT NOT NULL,
    prior_head_digest_sha256_hex  TEXT,
    signed_at                     TEXT NOT NULL,
    signature_classical           TEXT NOT NULL,
    signature_pqc                 TEXT,
    admitted_at                   TEXT NOT NULL,
    PRIMARY KEY (lineage_key_id, head_digest_sha256_hex, witness_key_id)
);
CREATE INDEX IF NOT EXISTS idx_lineage_head_cosigns_lineage
    ON federation_lineage_head_cosigns (lineage_key_id, signed_at);
