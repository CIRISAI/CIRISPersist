-- V107 (CIRISPersist#456) — expression index for the composer/retraction
-- lookups that `resolve_scores` (composer fetch) and `list_scores`
-- (LifecycleView `NOT EXISTS` subquery) run. Both key on
-- (attesting_key_id, attestation_type ∈ {supersedes,withdraws,recants},
-- json_extract(envelope,'$.references_attestation_id')) — previously an
-- unindexed correlated scan per candidate row (the most expensive predicate
-- at admission/sweep cardinality). SQLite supports the expression index.
CREATE INDEX IF NOT EXISTS federation_attestations_composer_ref
    ON federation_attestations (
        attesting_key_id,
        attestation_type,
        json_extract(attestation_envelope, '$.references_attestation_id')
    );
