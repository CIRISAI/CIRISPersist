-- V190 — the holder directory, keyed by the blob a holding claim cites, Postgres dialect
-- v55.0.0 (CIRISPersist#989, CC 3.1.3.3 / 5.3.2.1, CIRISConstitution#141)
--
-- SQLITE PARITY: migrations/sqlite/lens/V190__holding_claim_citation_index.sql
-- See that file's header for the rationale. The expression is spelled
-- exactly as the read spells it (the column is TEXT since V122, read through
-- a `::jsonb` cast); `COLLATE "C"` on `dimension` as on V137 / V178 / V180.

CREATE INDEX IF NOT EXISTS federation_attestations_dimension_citation
    ON cirislens.federation_attestations (
        (dimension COLLATE "C"),
        (attestation_envelope::jsonb->'evidence_refs'->>0)
    );
