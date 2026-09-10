-- V138 — community DEK key state + the epoch reverse seek, Postgres dialect
-- v43.0.0 (FSD/BLOB_ENCRYPTION_AT_REST.md §10.5, §10.9)
--
-- SQLITE PARITY: migrations/sqlite/lens/V138__community_dek_key_state_and_epoch_seek.sql
-- See that file's header for the full rationale — the Tink keyset state
-- machine, why the DESTROY precondition cannot live in a CHECK, why the
-- reverse seek is a correctness enabler rather than a perf nicety, and the
-- OpenMLS past-epoch retention policy this mirrors.

ALTER TABLE cirislens.federation_community_dek
    ADD COLUMN key_state TEXT NOT NULL DEFAULT 'enabled'
        CHECK (key_state IN ('enabled', 'disabled', 'destroyed'));

CREATE INDEX IF NOT EXISTS federation_community_blob_epoch_by_community_epoch
    ON cirislens.federation_community_blob_epoch (community_key_id, epoch);

ALTER TABLE cirislens.federation_community_dek_epoch
    ADD COLUMN retain_past_epochs INTEGER
        CHECK (retain_past_epochs IS NULL OR retain_past_epochs >= 0);
