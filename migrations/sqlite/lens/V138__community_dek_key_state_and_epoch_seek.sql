-- V138 — community DEK key state + the epoch reverse seek, SQLite dialect
-- v43.0.0 (FSD/BLOB_ENCRYPTION_AT_REST.md §10.5, §10.9)
--
-- POSTGRES PARITY: migrations/postgres/lens/V138__community_dek_key_state_and_epoch_seek.sql
--
-- Three additions, none of which rebuild a table.
--
-- 1. `federation_community_dek.key_state` — the Tink keyset state machine.
--
--    We adopt Tink's SEMANTICS and not the `tink-rust` crate (§10.4): one
--    primary, old keys retained decrypt-only, a key id carried with the
--    ciphertext. Our schema was already three-quarters of a keyset —
--    `federation_community_dek` is the keyset, `federation_community_dek_epoch`
--    is the primary pointer, `federation_community_blob_epoch` is the key id.
--    The missing quarter is PER-KEY STATE, and without it "stop using this
--    epoch" and "destroy this epoch's key" are the same operation.
--
--      enabled    the primary; new seals use it
--      disabled   no new seals, still decrypts. This is AV-70's ratified
--                 "forward-only / once shared, always shared" behaviour —
--                 now ONE STATE among three rather than the only option.
--      destroyed  key material gone; content under it is unreadable
--
--    THE DESTROY PRECONDITION IS NOT ENFORCED BY THIS MIGRATION and must be
--    enforced in code (§10.5): an epoch may move to `destroyed` only once
--    every object sealed under it has been re-sealed under a live epoch or
--    evicted from every holder. Destroying a DEK whose content still exists
--    does not erase the content — it ORPHANS it, turning a confidentiality
--    operation into unrecoverable data loss. A CHECK constraint cannot see
--    the blob rows, so the schema can only make the state expressible; the
--    refusal lives at the door.
--
--    Default `enabled` is correct for every existing row: there are no
--    communities yet, and a pre-existing epoch that was in use was, by
--    definition, usable.
--
-- 2. The REVERSE SEEK on `federation_community_blob_epoch`.
--
--    Its PK is `at_rest_sha256` alone, so "which objects are sealed at
--    (community, epoch)" — the core rotation and destroy-precondition query —
--    was a full table scan. That is not a performance nit: a precondition
--    that is expensive to check is a precondition that gets skipped, and the
--    thing it guards is unrecoverable.
--
--    The self/family plane already has the analogous seek
--    (`federation_blob_key_grants_by_recipient`, and
--    `(cohort_scope, recipient_key_id)`), so this closes an asymmetry rather
--    than inventing an index.
--
-- 3. `federation_community_dek_epoch.retain_past_epochs`.
--
--    OpenMLS ships a configurable past-epoch deletion policy because a
--    delivery service cannot guarantee epoch-N content arrives before epoch
--    N+1 begins. The same is true of a fountained corpus. Retaining every
--    epoch forever is unbounded; destroying eagerly orphans in-flight
--    content. NULL = retain indefinitely (today's behaviour, made explicit
--    rather than implicit).

ALTER TABLE federation_community_dek
    ADD COLUMN key_state TEXT NOT NULL DEFAULT 'enabled'
        CHECK (key_state IN ('enabled', 'disabled', 'destroyed'));

CREATE INDEX IF NOT EXISTS federation_community_blob_epoch_by_community_epoch
    ON federation_community_blob_epoch (community_key_id, epoch);

ALTER TABLE federation_community_dek_epoch
    ADD COLUMN retain_past_epochs INTEGER
        CHECK (retain_past_epochs IS NULL OR retain_past_epochs >= 0);
