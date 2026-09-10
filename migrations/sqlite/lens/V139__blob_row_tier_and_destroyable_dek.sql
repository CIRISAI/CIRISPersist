-- V139 — the blob row records its tier; a destroyed DEK holds no key, SQLite dialect
-- v43.0.0 (FSD/BLOB_ENCRYPTION_AT_REST.md §11.1, §11.4)
--
-- POSTGRES PARITY: migrations/postgres/lens/V139__blob_row_tier_and_destroyable_dek.sql
--
-- 1. `federation_blobs.cohort_scope` — THE ROW IS THE AUTHORITY ON ITS TIER.
--
--    Before this, nothing recorded which cohort a blob was stored under, so a
--    read had to decide "is this sealed?" by sniffing the body for the
--    envelope magic. That is two defects in one: a commons document that
--    happened to begin with the magic was routed down the encrypted path and
--    refused to every reader, and a plaintext body under a private cohort
--    was served to anyone. When the row says what it is, "is this sealed?"
--    becomes "does this row's tier require sealing, and does its body parse
--    as an envelope?" — a structural check, not a guess.
--
--    Backfill: every pre-V139 row is `federation`. Blob storage had not
--    shipped, so there is no encrypted legacy, and this migration does not
--    pretend to classify rows it cannot see the origin of.
--
-- 2. `federation_community_dek.wrapped_dek` becomes NULLABLE — because
--    DESTROY MUST DELETE KEY MATERIAL. A `destroyed` epoch row stays (it is
--    the tombstone that refuses re-enable and refuses binds) but its
--    self-retention wrap is gone, and the same transaction deletes every
--    member-grant row. A text column that says "destroyed" while every wrap
--    survives is a read-door refusal, not destruction — the first
--    implementation shipped exactly that.
--
--    SQLite cannot drop NOT NULL in place, so the table is rebuilt. This
--    one uses the `__v139` + RENAME shape, which is SAFE HERE and only
--    here: federation_community_dek has no self-FK, nothing references it,
--    and it has no indexes beyond the PK. That shape BREAKS on a table with
--    a self-FK (COMMIT refused with foreign_key_check clean — V136's
--    header); do not copy this file as a template for such a table.

ALTER TABLE federation_blobs
    ADD COLUMN cohort_scope TEXT NOT NULL DEFAULT 'federation'
        CHECK (cohort_scope IN ('self', 'family', 'community', 'affiliations',
                                'species', 'biosphere', 'federation'));

-- §11.1 — the tier the write door RESOLVED (directory included), which is
-- what reads dispatch on. `cohort_scope` above is the cohort the write
-- NAMED, kept as provenance. A `self`/`family` row can never be plaintext;
-- `community`/`affiliations` may be (the CC 4.4.3.2.1 infrastructure
-- carve-out); commons is always plaintext.
ALTER TABLE federation_blobs
    ADD COLUMN crypto_tier TEXT NOT NULL DEFAULT 'plaintext'
        CHECK (crypto_tier IN ('plaintext', 'invisible_encrypted', 'community_dek'));

-- §11.1 backfill — classify every PRE-EXISTING row from its OWN evidence.
-- Blob storage HAD shipped before this migration (put_blob_encrypted_self_family
-- since v42; the community cascade since V087), so a default of "commons"
-- would serve legacy ciphertext rows to anyone. Order matters: a binding
-- wins over a grant (the community cascade also writes a self-retention
-- grant row), and only rows with neither stay commons.
UPDATE federation_blobs
   SET cohort_scope = COALESCE(
           (SELECT g.cohort_scope FROM federation_blob_key_grants g
             WHERE g.at_rest_sha256 = federation_blobs.sha256
               AND g.cohort_scope IN ('self', 'family')
             LIMIT 1),
           cohort_scope),
       crypto_tier = 'invisible_encrypted'
 WHERE EXISTS (SELECT 1 FROM federation_blob_key_grants g
                WHERE g.at_rest_sha256 = federation_blobs.sha256
                  AND g.cohort_scope IN ('self', 'family'));

UPDATE federation_blobs
   SET cohort_scope = 'community',
       crypto_tier = 'community_dek'
 WHERE EXISTS (SELECT 1 FROM federation_community_blob_epoch e
                WHERE e.at_rest_sha256 = federation_blobs.sha256);

-- §11.5 / I19 — satellites whose blob is already gone (earlier eviction
-- paths deleted only the blob row). From here on `delete_blob` removes
-- them transactionally; this clears what those paths left.
DELETE FROM federation_community_blob_epoch
 WHERE at_rest_sha256 NOT IN (SELECT sha256 FROM federation_blobs);
DELETE FROM federation_blob_key_grants
 WHERE at_rest_sha256 NOT IN (SELECT sha256 FROM federation_blobs);

CREATE TABLE federation_community_dek__v139 (
    community_key_id  TEXT NOT NULL,
    epoch             INTEGER NOT NULL CHECK (epoch >= 0),
    wrap_algorithm    TEXT NOT NULL
        CHECK (wrap_algorithm IN ('aes256_gcm_content_master')),
    -- NULL iff key_state = 'destroyed': the material is gone.
    wrapped_dek       TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    key_state         TEXT NOT NULL DEFAULT 'enabled'
        CHECK (key_state IN ('enabled', 'disabled', 'destroyed')),
    CHECK ((key_state = 'destroyed') = (wrapped_dek IS NULL)),
    PRIMARY KEY (community_key_id, epoch)
);
INSERT INTO federation_community_dek__v139
    (community_key_id, epoch, wrap_algorithm, wrapped_dek, created_at, key_state)
SELECT community_key_id, epoch, wrap_algorithm, wrapped_dek, created_at, key_state
  FROM federation_community_dek;
DROP TABLE federation_community_dek;
ALTER TABLE federation_community_dek__v139 RENAME TO federation_community_dek;
