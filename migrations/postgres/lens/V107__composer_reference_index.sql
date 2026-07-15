-- V107 (CIRISPersist#456) — expression index for the composer/retraction
-- lookups `resolve_scores` (composer fetch) + `list_scores` (LifecycleView
-- NOT EXISTS subquery) run: (attesting_key_id, attestation_type,
-- (attestation_envelope->>'references_attestation_id')). Previously an
-- unindexed correlated scan per candidate row. Backend-symmetric with the
-- SQLite V107 expression index.
CREATE INDEX IF NOT EXISTS federation_attestations_composer_ref
    ON cirislens.federation_attestations (
        attesting_key_id,
        attestation_type,
        (attestation_envelope->>'references_attestation_id')
    );
