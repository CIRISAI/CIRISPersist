-- V145 — an epoch belongs to its MINTER: `minter_key_id` on every community-DEK
-- key-state table, PostgreSQL dialect
-- v44.3.0 (CIRISPersist#848, FSD/BLOB_REPLICATION.md §11, §16)
--
-- SQLITE PARITY: migrations/sqlite/lens/V145__per_minter_dek_epochs.sql
-- (four table rebuilds there — see that file for the full reasoning: the
-- fork ruling, the sentinel, and why only the running node can resolve it.)
--
-- Postgres can ADD COLUMN, backfill, DROP the default and swap the PRIMARY
-- KEY in place, so this twin is the same change in ALTER form. The column is
-- added with the sentinel as its default so the backfill of existing rows is
-- one statement and the NOT NULL holds from the first instant; the default is
-- then DROPPED — every writer binds `minter_key_id` explicitly, and a row that
-- reached the table without one must fail loudly, not quietly become
-- `__this_node__` after the boot-time resolution has already run.
--
-- Refinery wraps this migration in its own transaction.

-- ── the current sealing epoch, PER MINTER ────────────────────────────────
ALTER TABLE cirislens.federation_community_dek_epoch
    ADD COLUMN minter_key_id TEXT NOT NULL DEFAULT '__this_node__';
ALTER TABLE cirislens.federation_community_dek_epoch
    ALTER COLUMN minter_key_id DROP DEFAULT;
ALTER TABLE cirislens.federation_community_dek_epoch
    DROP CONSTRAINT federation_community_dek_epoch_pkey;
-- `community_key_id` was NOT NULL by virtue of being the whole PRIMARY KEY;
-- now that it is half of one, say so on the column itself, as the sqlite
-- rebuild does — the two trees must agree column by column (#828).
ALTER TABLE cirislens.federation_community_dek_epoch
    ALTER COLUMN community_key_id SET NOT NULL;
ALTER TABLE cirislens.federation_community_dek_epoch
    ADD PRIMARY KEY (community_key_id, minter_key_id);

-- ── self-retention + key state, PER MINTER, with `minted_at` (§15) ───────
ALTER TABLE cirislens.federation_community_dek
    ADD COLUMN minter_key_id TEXT NOT NULL DEFAULT '__this_node__';
ALTER TABLE cirislens.federation_community_dek
    ALTER COLUMN minter_key_id DROP DEFAULT;
ALTER TABLE cirislens.federation_community_dek
    ADD COLUMN minted_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
-- Every existing row was minted when it was created.
UPDATE cirislens.federation_community_dek SET minted_at = created_at;
ALTER TABLE cirislens.federation_community_dek
    DROP CONSTRAINT federation_community_dek_pkey;
ALTER TABLE cirislens.federation_community_dek
    ADD PRIMARY KEY (community_key_id, minter_key_id, epoch);

-- ── member grants, PER MINTER ────────────────────────────────────────────
ALTER TABLE cirislens.federation_community_dek_member_grants
    ADD COLUMN minter_key_id TEXT NOT NULL DEFAULT '__this_node__';
ALTER TABLE cirislens.federation_community_dek_member_grants
    ALTER COLUMN minter_key_id DROP DEFAULT;
ALTER TABLE cirislens.federation_community_dek_member_grants
    DROP CONSTRAINT federation_community_dek_member_grants_pkey;
ALTER TABLE cirislens.federation_community_dek_member_grants
    ADD PRIMARY KEY (community_key_id, minter_key_id, epoch, member_key_id);

-- ── the blob binding: the minter is the row's author where known ─────────
ALTER TABLE cirislens.federation_community_blob_epoch
    ADD COLUMN minter_key_id TEXT NOT NULL DEFAULT '__this_node__';
ALTER TABLE cirislens.federation_community_blob_epoch
    ALTER COLUMN minter_key_id DROP DEFAULT;
UPDATE cirislens.federation_community_blob_epoch e
   SET minter_key_id = b.author_key_id
  FROM cirislens.federation_blobs b
 WHERE b.sha256 = e.at_rest_sha256
   AND b.author_key_id IS NOT NULL;

-- V138's reverse seek, re-keyed on the full epoch identity.
DROP INDEX IF EXISTS cirislens.federation_community_blob_epoch_by_community_epoch;
CREATE INDEX IF NOT EXISTS federation_community_blob_epoch_by_community_epoch
    ON cirislens.federation_community_blob_epoch (community_key_id, minter_key_id, epoch);

COMMENT ON COLUMN cirislens.federation_community_dek.minter_key_id IS
    'The occurrence whose cascade minted this epoch (CIRISPersist#848). `__this_node__` only between V145 and the boot-time resolution; a surviving sentinel aborts the boot.';
COMMENT ON COLUMN cirislens.federation_community_dek.minted_at IS
    'When this minter minted the DEK; a removal admitted after it rotates the counter before the next seal (BLOB_REPLICATION.md §15).';
