-- V182 — admit 'affiliations' into federation_group_versions.cohort (SQLite dialect)
--        v54.0.0 (CIRISPersist#1034, CC 4.4.3.2.8).
--
-- POSTGRES PARITY: migrations/postgres/lens/V182__group_versions_affiliations.sql
-- (same value admitted there; see that file for why). V089's
-- `CHECK (cohort IN ('family', 'community'))` refused every supersession of an
-- affiliation, which records its prior version under `affiliations`.
--
-- HOW: SQLite bakes the CHECK into CREATE TABLE, so the table is rebuilt.
-- Nothing references `federation_group_versions` (no inbound FK, no self-FK,
-- no trigger), so the drop fires no cascade and moves no deferred-FK counter.
-- The rows are staged in a copy, the table is dropped and re-created
-- under its FINAL name (no `_new` table and no rename — the V136 shape), the
-- rows are restored, and the index is re-created.

CREATE TABLE _v182_stage_group_versions AS
    SELECT cohort, group_key_id, version, snapshot, change_authorization,
           superseded_at, persist_row_hash
    FROM federation_group_versions;

DROP TABLE federation_group_versions;

CREATE TABLE federation_group_versions (
    cohort            TEXT NOT NULL
        CHECK (cohort IN ('family', 'community', 'affiliations')),
    group_key_id      TEXT NOT NULL,
    version           INTEGER NOT NULL,
    snapshot          TEXT NOT NULL
        CHECK (json_valid(snapshot)),
    change_authorization TEXT
        CHECK (change_authorization IS NULL OR json_valid(change_authorization)),
    superseded_at     TEXT NOT NULL,    -- RFC-3339
    persist_row_hash  TEXT NOT NULL,
    PRIMARY KEY (cohort, group_key_id, version)
);

INSERT INTO federation_group_versions
    (cohort, group_key_id, version, snapshot, change_authorization,
     superseded_at, persist_row_hash)
SELECT cohort, group_key_id, version, snapshot, change_authorization,
       superseded_at, persist_row_hash
FROM _v182_stage_group_versions;

DROP TABLE _v182_stage_group_versions;

CREATE INDEX IF NOT EXISTS federation_group_versions_by_group
    ON federation_group_versions (cohort, group_key_id);
