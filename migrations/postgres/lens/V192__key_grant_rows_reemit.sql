-- V192 — the key-grant SET is retired; every emission axis goes dirty so a
-- node re-emits the wraps it holds as per-recipient rows. PostgreSQL dialect.
-- v55.0.0 (CIRISPersist#989, CC 3.3.2 rc7, CIRISConstitution#143).
--
-- SQLITE PARITY: migrations/sqlite/lens/V192__key_grant_rows_reemit.sql — the
-- WHY is there. Data only: the V146 ledger reset (every axis dirty, so the
-- boot sweep re-emits each wrap a node holds as sealer or minter as a
-- per-recipient row) and the pending index of retired sets dropped.
UPDATE cirislens.federation_community_dek SET key_grant_emitted_at = NULL
 WHERE key_grant_emitted_at IS NOT NULL;
UPDATE cirislens.federation_blobs SET key_grant_emitted_at = NULL
 WHERE key_grant_emitted_at IS NOT NULL;
UPDATE cirislens.federation_stream_deks SET key_grant_emitted_at = NULL
 WHERE key_grant_emitted_at IS NOT NULL;
DELETE FROM cirislens.federation_key_grant_pending;
