-- V140 — the epoch binding survives eviction, stamped `evicted_at`, Postgres dialect
-- #833 (FSD/BLOB_ENCRYPTION_AT_REST.md §11.5, I31)
--
-- SQLITE PARITY: migrations/sqlite/lens/V140__blob_epoch_binding_evicted_at.sql
-- See that file's header for the rationale.

ALTER TABLE cirislens.federation_community_blob_epoch
    ADD COLUMN evicted_at TIMESTAMPTZ;
