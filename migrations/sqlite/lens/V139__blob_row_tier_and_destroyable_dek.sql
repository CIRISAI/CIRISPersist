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
--    SQLite cannot drop NOT NULL in place, so the table is re-created under
--    its FINAL name (never `_new` + RENAME — see V136's header for why that
--    shape breaks). No self-FK, no dependents referencing it, no indexes
--    beyond the PK, so the rebuild is the simple case.

ALTER TABLE federation_blobs
    ADD COLUMN cohort_scope TEXT NOT NULL DEFAULT 'federation'
        CHECK (cohort_scope IN ('self', 'family', 'community', 'affiliations',
                                'species', 'biosphere', 'federation'));

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
