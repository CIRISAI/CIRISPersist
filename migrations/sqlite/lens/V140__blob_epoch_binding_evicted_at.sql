-- V140 — the epoch binding survives eviction, stamped `evicted_at`, SQLite dialect
-- #833 (FSD/BLOB_ENCRYPTION_AT_REST.md §11.5, I31)
--
-- POSTGRES PARITY: migrations/postgres/lens/V140__blob_epoch_binding_evicted_at.sql
--
-- After a retention sweep, v43.0.0 reported an evicted community blob as
-- "carries no community-DEK binding" — indistinguishable from a sha that
-- was never ours, because the sweep deleted the binding with the bytes
-- (I19's discipline, applied to the sweep). The binding is the only path
-- from a sha back to the (community, epoch) whose retention swept it, so
-- the sweep now KEEPS the binding and stamps this column. NULL = the
-- binding is live (its blob row exists); non-NULL = the sweep deleted the
-- local copy at that instant.
--
-- `community_dek_epoch_object_count` counts only `evicted_at IS NULL`, so
-- the destroy precondition is unchanged; `delete_blob` (the generic floor)
-- still deletes the binding outright — only the SWEEP marks, because only
-- the sweep is a policy action a reader should be told about. Cost: one
-- small row per blob that once existed under a community epoch — bounded
-- by the corpus that was, not by time.
--
-- No backfill: bindings the pre-#833 sweep deleted are gone, and V139
-- already removed any binding whose blob was missing. Nothing to stamp.

ALTER TABLE federation_community_blob_epoch
    ADD COLUMN evicted_at TEXT;
