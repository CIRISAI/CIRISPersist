-- V181 — structural composers keyed by the row they name, Postgres dialect
-- v53.1.7 (CIRISEdge PR #818)
--
-- SQLITE PARITY: migrations/sqlite/lens/V181__composer_reference_seek_index.sql
-- See that file's header for the rationale. The expression is spelled
-- exactly as the read spells it (the column is TEXT since V122, read through
-- a `::jsonb` cast — V122's rebuilt `composer_ref` uses the same spelling).

CREATE INDEX IF NOT EXISTS federation_attestations_reference_seek
    ON cirislens.federation_attestations (
        ((attestation_envelope::jsonb ->> 'references_attestation_id')),
        attestation_type
    );
