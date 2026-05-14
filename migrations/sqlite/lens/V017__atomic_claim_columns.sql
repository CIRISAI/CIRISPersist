-- V017 — atomic-claim columns, SQLite dialect (v1.0.0; CIRISAgent#756 #2).
--
-- Postgres parity (postgres/lens/V017): adds nullable + UNIQUE
-- content-hash columns to the secrets + audit tables to enable the
-- atomic-claim primitive. Dialect translations:
--
--   PostgreSQL                       → SQLite
--   ────────────────────────────────────────────────────────────────
--   BYTEA UNIQUE                     → BLOB UNIQUE (same semantics)
--   ALTER TABLE … ADD CONSTRAINT     → CREATE UNIQUE INDEX
--   COMMENT ON COLUMN                → (no-op; SQLite has no per-
--                                       column comments)
--
-- NULL + UNIQUE semantics in SQLite: "For the purposes of unique
-- indices, all NULL values are considered different from all other
-- values, including other NULLs." This matches PG's NULLS DISTINCT
-- default — existing rows can carry NULL freely, only non-null
-- values must be unique. No partial index is required.
--
-- See postgres/lens/V017 header for the full design rationale
-- (hmac vs hash split, why nullable, threat-model anchors).

ALTER TABLE cirislens_secrets_secrets
    ADD COLUMN content_hmac BLOB;

CREATE UNIQUE INDEX IF NOT EXISTS secrets_content_hmac_key
    ON cirislens_secrets_secrets (content_hmac)
    WHERE content_hmac IS NOT NULL;

ALTER TABLE cirislens_audit_log
    ADD COLUMN content_hash BLOB;

CREATE UNIQUE INDEX IF NOT EXISTS audit_log_content_hash_key
    ON cirislens_audit_log (content_hash)
    WHERE content_hash IS NOT NULL;
