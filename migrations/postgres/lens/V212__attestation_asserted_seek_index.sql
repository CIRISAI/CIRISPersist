-- V212 — the attestation listing's keyset order, Postgres dialect. v61
-- (the canonical's read storm).
--
-- SQLITE PARITY: migrations/sqlite/lens/V212__attestation_asserted_seek_index.sql
-- See that file's header for the rationale. Postgres had no index leading
-- on `asserted_at` either (V004's attester / subject pairs, V060's
-- by-target), so the unpinned listing sorted every qualifying row before
-- its LIMIT. Plain CREATE INDEX inside the migration transaction (V042's
-- precedent), not CONCURRENTLY.

CREATE INDEX IF NOT EXISTS federation_attestations_asserted_seek
    ON cirislens.federation_attestations (asserted_at DESC, attestation_id DESC);

-- And the composers' reference over composer rows only (see the sqlite
-- file): the twin of the sqlite partial index, so both dialects carry the
-- same index set. Postgres's statistics track the NULL fraction, so its
-- planner was not misled; the index is parity, not a fix here.
CREATE INDEX IF NOT EXISTS federation_attestations_reference_live
    ON cirislens.federation_attestations (
        ((attestation_envelope::jsonb ->> 'references_attestation_id')),
        attestation_type
    )
    WHERE (attestation_envelope::jsonb ->> 'references_attestation_id') IS NOT NULL;
