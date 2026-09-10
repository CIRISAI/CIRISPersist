-- V139 — the blob row records its tier; a destroyed DEK holds no key, Postgres dialect
-- v43.0.0 (FSD/BLOB_ENCRYPTION_AT_REST.md §11.1, §11.4)
--
-- SQLITE PARITY: migrations/sqlite/lens/V139__blob_row_tier_and_destroyable_dek.sql
-- See that file's header for the rationale. Postgres can ALTER in place.

ALTER TABLE cirislens.federation_blobs
    ADD COLUMN cohort_scope TEXT NOT NULL DEFAULT 'federation'
        CHECK (cohort_scope IN ('self', 'family', 'community', 'affiliations',
                                'species', 'biosphere', 'federation'));

-- §11.1 — the tier the write door RESOLVED (directory included), which is
-- what reads dispatch on. See the sqlite twin for the full note.
ALTER TABLE cirislens.federation_blobs
    ADD COLUMN crypto_tier TEXT NOT NULL DEFAULT 'plaintext'
        CHECK (crypto_tier IN ('plaintext', 'invisible_encrypted', 'community_dek'));

-- §11.1 backfill — classify every PRE-EXISTING row from its OWN evidence
-- (a grant ⇒ invisible_encrypted under the grant's cohort; a binding ⇒
-- community_dek; neither ⇒ commons). Binding wins over grant.
UPDATE cirislens.federation_blobs b
   SET cohort_scope = COALESCE(
           (SELECT g.cohort_scope FROM cirislens.federation_blob_key_grants g
             WHERE g.at_rest_sha256 = b.sha256
               AND g.cohort_scope IN ('self', 'family')
             LIMIT 1),
           b.cohort_scope),
       crypto_tier = 'invisible_encrypted'
 WHERE EXISTS (SELECT 1 FROM cirislens.federation_blob_key_grants g
                WHERE g.at_rest_sha256 = b.sha256
                  AND g.cohort_scope IN ('self', 'family'));

UPDATE cirislens.federation_blobs b
   SET cohort_scope = 'community',
       crypto_tier = 'community_dek'
 WHERE EXISTS (SELECT 1 FROM cirislens.federation_community_blob_epoch e
                WHERE e.at_rest_sha256 = b.sha256);

-- §11.5 / I19 — satellites whose blob is already gone.
DELETE FROM cirislens.federation_community_blob_epoch
 WHERE at_rest_sha256 NOT IN (SELECT sha256 FROM cirislens.federation_blobs);
DELETE FROM cirislens.federation_blob_key_grants
 WHERE at_rest_sha256 NOT IN (SELECT sha256 FROM cirislens.federation_blobs);

ALTER TABLE cirislens.federation_community_dek
    ALTER COLUMN wrapped_dek DROP NOT NULL;
ALTER TABLE cirislens.federation_community_dek
    ADD CONSTRAINT federation_community_dek_destroyed_has_no_key
        CHECK ((key_state = 'destroyed') = (wrapped_dek IS NULL));
