-- V180 — a device's custody reports, keyed by the blob they cite, Postgres dialect
-- v53.1.6 (CIRISEdge's heap harness)
--
-- SQLITE PARITY: migrations/sqlite/lens/V180__custody_ack_citation_index.sql
-- See that file's header for the rationale. The expression is spelled
-- exactly as the read spells it (the column is TEXT since V122, read through
-- a `::jsonb` cast); `COLLATE "C"` on `dimension` as on V137 / V178, so the
-- equality seek and the prefix range share one index shape.

CREATE INDEX IF NOT EXISTS federation_attestations_attester_dimension_citation
    ON cirislens.federation_attestations (
        attesting_key_id,
        (dimension COLLATE "C"),
        (attestation_envelope::jsonb->'evidence_refs'->>0)
    );
