-- V178 — the attested-keyed seeks behind the bounded audience and consent
-- reads, Postgres dialect
-- v53.1.5 (CIRISServer's canonical node, heap +500 MB vs v52, 2026-10-06)
--
-- SQLITE PARITY: migrations/sqlite/lens/V178__attested_seek_indexes.sql
-- See that file's header for the rationale.
--
-- `COLLATE "C"` on the dimension column is LOAD-BEARING, as on V137: the
-- prefix reads compare half-open byte ranges, and only a "C"-collated
-- index serves `dimension COLLATE "C" >= $a AND dimension COLLATE "C" < $b`.
-- The composer expression is spelled exactly as the reads spell it
-- (`attestation_envelope::jsonb->>'references_attestation_id'` — the
-- column is read through a `::jsonb` cast everywhere, and an expression
-- index matches only its own spelling). Refinery wraps each migration in a
-- transaction: plain CREATE INDEX, not CONCURRENTLY (V042's precedent).

CREATE INDEX IF NOT EXISTS federation_attestations_attested_dimension
    ON cirislens.federation_attestations (attested_key_id, (dimension COLLATE "C"));

CREATE INDEX IF NOT EXISTS federation_attestations_attested_composer_ref
    ON cirislens.federation_attestations (
        attested_key_id,
        attestation_type,
        (attestation_envelope::jsonb->>'references_attestation_id')
    );
