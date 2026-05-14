-- V017 — atomic-claim columns (CIRISPersist v1.0.0; CIRISAgent#756 concern #2).
--
-- Adds nullable, UNIQUE content-hash columns to the secrets store and
-- the audit log so callers can race-safely "claim" an envelope: the
-- first writer wins the INSERT; subsequent writers with the same
-- content hash observe a UNIQUE-violation and fall through to the
-- existing row's identifier. The agent's N-worker pipeline calls
-- through this surface so two workers processing the same envelope
-- end up with one row, not two.
--
-- # Why nullable
--
-- The columns are added as nullable so the existing
-- store_secret / record_entry write paths (which don't compute the
-- hash) keep working unchanged. Only the new typed surfaces
-- (`try_claim_secret`, `try_claim_event`) populate the hash. Legacy
-- rows stay NULL forever.
--
-- # Why UNIQUE (not partial)
--
-- PostgreSQL's UNIQUE constraint treats two NULLs as distinct
-- (SQL:2008 default for NULLS NOT DISTINCT was opt-in until PG 15;
-- our policy across the persist substrate is the SQL-standard NULLS
-- DISTINCT, which is also the PG default). Many existing rows can
-- carry NULL without conflict; only NON-NULL values must be unique.
-- A partial index `WHERE content_hash IS NOT NULL` is functionally
-- equivalent but adds a second lookup name; the plain UNIQUE column
-- is simpler and the planner picks the implicit btree on
-- `content_hash` for the conflict-recovery SELECT.
--
-- # Why secrets uses content_hmac, audit uses content_hash
--
-- Secrets dedup keys must be master-key-bound: rotating the master
-- key resets dedup state intentionally (the same plaintext now
-- produces a different hmac). Audit content is non-sensitive — a
-- public sha256 is the right dedup key, and removes the
-- need to thread a key through every audit caller.
--
-- # Threat model anchor
--
-- AV-49 / AV-50 (audit chain integrity) and AV-15 (secrets
-- accountability) are unchanged. Atomic-claim only changes the
-- write-collision behavior; the chain checks + access_log audit
-- writes still gate every successful insert through the existing
-- code paths.

BEGIN;

-- ── secrets.content_hmac ────────────────────────────────────────────

ALTER TABLE cirislens_secrets.secrets
    ADD COLUMN IF NOT EXISTS content_hmac BYTEA;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'secrets_content_hmac_key'
    ) THEN
        ALTER TABLE cirislens_secrets.secrets
            ADD CONSTRAINT secrets_content_hmac_key UNIQUE (content_hmac);
    END IF;
END$$;

COMMENT ON COLUMN cirislens_secrets.secrets.content_hmac IS
    'v1.0.0 — HMAC-SHA256(active_master_key, plaintext) for atomic-claim dedup. NULL on rows written via the legacy store_secret path. UNIQUE; conflicts surface as ClaimResult::AlreadyClaimed.';

-- ── audit_log.content_hash ──────────────────────────────────────────

ALTER TABLE cirislens.audit_log
    ADD COLUMN IF NOT EXISTS content_hash BYTEA;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'audit_log_content_hash_key'
    ) THEN
        ALTER TABLE cirislens.audit_log
            ADD CONSTRAINT audit_log_content_hash_key UNIQUE (content_hash);
    END IF;
END$$;

COMMENT ON COLUMN cirislens.audit_log.content_hash IS
    'v1.0.0 — sha256(canonical_envelope_bytes) for atomic-claim dedup. NULL on rows written via the legacy record_entry path. UNIQUE; conflicts surface as ClaimResult::AlreadyClaimed.';

COMMIT;
