-- V057 — peer-level cohort_scope membership read index — SQLite
--        dialect (CIRISPersist#151, v3.9.3).
--
-- Postgres parity (postgres/lens/V057): functional partial index over
-- the federation_peer_metadata policy_blob `cohort_scope` slot for
-- live peers, backing FederationKeyFilter.cohort_scope.
--
-- SQLite extracts the slot via json_extract(policy_blob,
-- '$.cohort_scope') (the Postgres `policy_blob->>'cohort_scope'`
-- equivalent). Partial (removed_at IS NULL AND policy_blob IS NOT
-- NULL) so it covers only the live, cohort-tagged rows the filter
-- probes. See migrations/postgres/lens/V057 for the full rationale.

CREATE INDEX IF NOT EXISTS federation_peer_metadata_cohort_scope
    ON federation_peer_metadata (json_extract(policy_blob, '$.cohort_scope'))
    WHERE removed_at IS NULL AND policy_blob IS NOT NULL;
