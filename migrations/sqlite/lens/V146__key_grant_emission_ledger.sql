-- V146 — the KeyGrant emission ledger and the pending-content index,
-- SQLite dialect
-- v44.3.0 (CIRISPersist#848 / PR #850 review, FSD/BLOB_REPLICATION.md §13, §14)
--
-- POSTGRES PARITY: migrations/postgres/lens/V146__key_grant_emission_ledger.sql
--
-- WHY
-- ---
-- A write door emits the epoch's KeyGrant set after the cascade that minted
-- or granted anew. If the process dies between the cascade's commit and the
-- emission, the local DEK and every recipient wrap are durable, the next
-- write finds the fan-out unchanged, and the epoch's key never leaves the
-- node while its ciphertext does. The cascade cannot be asked to remember
-- (it was the thing that died), so the ledger is on the row the cascade
-- already writes: `key_grant_emitted_at` on the epoch's self-retention row
-- (epoch axis) and on the blob row (content axis). An axis is DIRTY when
-- the column is NULL or not later than the newest grant row under it — the
-- grant tables already carry `created_at` — and every door emits when dirty,
-- marking on success. `Engine::emit_pending_key_grants` sweeps at boot.
--
-- The pending index: a content-axis set that arrives before its bytes is
-- admitted and not projected (the author is unknown); the adopt projects
-- the author-signed sets. Keyed by (sha, scope) so an adopt reads its own
-- rows and never scans an author's attestations.
--
-- Additive: two nullable columns and one table. No rebuild, no backfill.
ALTER TABLE federation_community_dek ADD COLUMN key_grant_emitted_at TEXT;
ALTER TABLE federation_blobs ADD COLUMN key_grant_emitted_at TEXT;

CREATE TABLE federation_key_grant_pending (
    at_rest_sha256   BLOB NOT NULL CHECK (length(at_rest_sha256) = 32),
    cohort_scope     TEXT NOT NULL,
    attestation_id   TEXT NOT NULL,
    signer_key_id    TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    PRIMARY KEY (at_rest_sha256, cohort_scope, attestation_id)
);
