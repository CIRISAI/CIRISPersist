-- V139 — the blob row records its tier; a destroyed DEK holds no key, Postgres dialect
-- v43.0.0 (FSD/BLOB_ENCRYPTION_AT_REST.md §11.1, §11.4)
--
-- SQLITE PARITY: migrations/sqlite/lens/V139__blob_row_tier_and_destroyable_dek.sql
-- See that file's header for the rationale. Postgres can ALTER in place.

ALTER TABLE cirislens.federation_blobs
    ADD COLUMN cohort_scope TEXT NOT NULL DEFAULT 'federation'
        CHECK (cohort_scope IN ('self', 'family', 'community', 'affiliations',
                                'species', 'biosphere', 'federation'));

ALTER TABLE cirislens.federation_community_dek
    ALTER COLUMN wrapped_dek DROP NOT NULL;
ALTER TABLE cirislens.federation_community_dek
    ADD CONSTRAINT federation_community_dek_destroyed_has_no_key
        CHECK ((key_state = 'destroyed') = (wrapped_dek IS NULL));
