-- V178 — the attested-keyed seeks behind the bounded audience and consent
-- reads, SQLite dialect
-- v53.1.5 (CIRISServer's canonical node, heap +500 MB vs v52, 2026-10-06)
--
-- POSTGRES PARITY: migrations/postgres/lens/V178__attested_seek_indexes.sql
--
-- Three per-call reads loaded an UNBOUNDED row set and decoded every
-- envelope: `owner_allow_list` read every row its owner ever authored to
-- find a handful of `consent:replication:v1` grants; `is_public_group` read
-- every row attested to a group to find its charter; the scoped consent
-- fold read every row attested to the target TWICE per call (the default
-- `resolve_scoped_stance`, then `resolve_scoped_stance_by_principals` for
-- the stewards) and cloned the filtered set per steward. On the canonical
-- (~22k attestations over ~2.5k keys; ~5.6k rows attested to canonical-1)
-- the scorer asked that fold once per agent per tick.
--
-- The reads are now shaped by what the fold can USE:
--
--   list_attestations_by_dimension_prefix(attester, prefix)
--       served by V137's (attesting_key_id, dimension)
--   list_attestations_for_dimension_prefix(attested, attester?, prefix)
--       served by the FIRST index below
--   list_composers_referencing_any(ids, attested?, attester?)
--       served by V107's (attesting_key_id, attestation_type, ref) when the
--       attester is pinned, and by the SECOND index below when the attested
--       key is — the consent fold and the charter check pin the TARGET, since
--       a composer that retires a row about T is itself attested to T.
--
-- Both are the attested-keyed twins of indexes the table already carries
-- (V137 / V107): same expressions, the other axis. `dimension` is V106's
-- VIRTUAL generated column; indexing it materialises the extraction into
-- the index exactly as V137 does. No backfill: an index is derived.

CREATE INDEX IF NOT EXISTS federation_attestations_attested_dimension
    ON federation_attestations (attested_key_id, dimension);

CREATE INDEX IF NOT EXISTS federation_attestations_attested_composer_ref
    ON federation_attestations (
        attested_key_id,
        attestation_type,
        json_extract(attestation_envelope, '$.references_attestation_id')
    );
