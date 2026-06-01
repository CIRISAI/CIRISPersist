-- V057 — peer-level cohort_scope membership read index
--        (CIRISPersist#151, v3.9.3).
--
-- Backs FederationKeyFilter.cohort_scope: the bulk "which key_ids
-- belong to cohort X?" reader added at the wheel surface. The filter
-- EXISTS-joins federation_peer_metadata and matches the policy_blob
-- JSONB `cohort_scope` slot for *live* peers (removed_at IS NULL).
--
-- This functional partial index keeps that lookup O(log N) instead of
-- a full peer-metadata scan. Partial (removed_at IS NULL AND
-- policy_blob IS NOT NULL) so it only covers the live, cohort-tagged
-- rows the filter actually probes — soft-removed and untagged peers
-- never enter the index.
--
-- Note this is the PEER-level cohort_scope (free-form membership label,
-- e.g. 'family-acme'), distinct from the V056 envelope-level closed-set
-- federation_attestations.cohort_scope.

CREATE INDEX IF NOT EXISTS federation_peer_metadata_cohort_scope
    ON cirislens.federation_peer_metadata ((policy_blob->>'cohort_scope'))
    WHERE removed_at IS NULL AND policy_blob IS NOT NULL;
