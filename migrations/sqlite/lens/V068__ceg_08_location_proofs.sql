-- V068 — CEG 0.8 §5.6.8.11 + §0.8.1 location_proof substrate
--        (CIRISPersist#154, v4.10.0) — SQLite dialect. Postgres parity:
--        postgres/lens/V068. See that file for the full rationale.
--
-- BYTEA → BLOB; TIMESTAMPTZ → TEXT (RFC-3339); the §0.8.1 rough-only
-- (resolution ≤ 7) + H3 canonical-form gate live in put_location_proof
-- (h3o), not the DDL. Refinery wraps this in its own transaction.

CREATE TABLE federation_location_proofs (
    subject_key_id        TEXT NOT NULL REFERENCES federation_keys(key_id),
    cell_id               TEXT NOT NULL,
    cell_resolution       INTEGER NOT NULL
        CHECK (cell_resolution BETWEEN 0 AND 15),
    asserted_at           TEXT NOT NULL,   -- RFC-3339
    valid_until           TEXT,            -- RFC-3339
    attestation_evidence  BLOB,
    withdrawn_at          TEXT,            -- null = in force
    persist_row_hash      TEXT NOT NULL,
    PRIMARY KEY (subject_key_id, asserted_at)
);

CREATE INDEX federation_location_proofs_by_subject_live
    ON federation_location_proofs (subject_key_id)
    WHERE withdrawn_at IS NULL;

CREATE INDEX federation_location_proofs_by_cell
    ON federation_location_proofs (cell_id);
