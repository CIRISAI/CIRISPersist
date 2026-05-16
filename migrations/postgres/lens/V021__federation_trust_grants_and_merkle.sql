-- V021 — Federation trust grants + per-tenant Merkle layer
-- (v1.5.0 Phase A, FEDERATION_TRUST_INTERFACE.md §2 + §4.4).
--
-- Phase A: schema only — projection tables for the new trust-grant
-- substrate. Source of truth is the audit chain
-- (`cirislens.audit_log`); the tables here are materialized views the
-- read API serves. Engine ingest-path rewire (Phase D) and PG
-- `TransparencyStore<AuditLeaf>` impl (Phase B) come later.
--
-- # What this migration adds
--
-- 1. **federation_trust_grants** — purpose-scoped grant projection.
--    Replaces V020's columnar trust hierarchy (`trust_type`,
--    `trust_relationship`, `trust_domains`, `trusted_at`,
--    `trusted_by`, `expires_at`) with a row-per-grant shape carrying
--    (grantee_key, granter_key, purpose, scope, granted_at,
--    expires_at, revoked_at, revoked_by, chain_event_id,
--    chain_event_hash, tenant_id).
--    Backfill from V020 lands in Phase F; until then both shapes
--    coexist and the trust column reads continue to work.
--
-- 2. **merkle_leaves** — leaf-to-event map for the per-tenant Merkle
--    tree. Every audit chain entry becomes one Merkle leaf under FSD
--    §4.4's every-append cadence; this table is the densely-indexed
--    `(tenant_id, leaf_index) → chain_event_id` projection the
--    `TransparencyStore<AuditLeaf>` impl reads.
--
-- 3. **merkle_sth_log** — signed tree head history. One row per leaf
--    append (every-append cadence). Read API exposes the latest STH
--    + STH-at-`tree_size` for consistency-proof reconstruction.
--
-- # Dialect / shape notes
--
-- * Tables live in the `cirislens.` schema, matching V004 / V014 /
--   V020 (the FSD §2 SQL is written un-schema-qualified; this file
--   adapts it to the persist convention).
-- * The FK target column on `federation_keys` is `key_id` (the V004
--   PK). The FSD draft uses the literal name `key`; persist's
--   migrations have always used `key_id`. References here resolve
--   against the real PK column.
--
-- # Refinery transaction wrapping
--
-- Per V019's header note: refinery wraps each migration in its own
-- transaction. NO explicit BEGIN/COMMIT in this file.

-- ─── federation_trust_grants ───────────────────────────────────────

CREATE TABLE cirislens.federation_trust_grants (
    grant_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    grantee_key        TEXT NOT NULL REFERENCES cirislens.federation_keys(key_id),
    granter_key        TEXT NOT NULL REFERENCES cirislens.federation_keys(key_id),
    purpose            TEXT NOT NULL
                       CHECK (purpose IN ('technical','deferral','contribution','service')),
    scope              TEXT NOT NULL,
    granted_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    revoked_by         TEXT REFERENCES cirislens.federation_keys(key_id),
    chain_event_id     BIGINT NOT NULL,
    chain_event_hash   BYTEA NOT NULL,
    tenant_id          TEXT NOT NULL,
    CHECK (granter_key != grantee_key),
    CHECK (revoked_at IS NULL OR revoked_by IS NOT NULL),
    UNIQUE (grantee_key, granter_key, purpose, scope)
);

CREATE INDEX idx_ftg_grantee_purpose ON cirislens.federation_trust_grants
    (grantee_key, purpose, scope) WHERE revoked_at IS NULL;
CREATE INDEX idx_ftg_granter ON cirislens.federation_trust_grants (granter_key);
CREATE INDEX idx_ftg_chain ON cirislens.federation_trust_grants (chain_event_id);
CREATE INDEX idx_ftg_tenant ON cirislens.federation_trust_grants (tenant_id);

-- ─── merkle_leaves ─────────────────────────────────────────────────
--
-- `canonical_bytes` is the RFC 6962 §2.1 hashing-form bytes (i.e. the
-- output of `AuditLeaf::canonical_bytes()` — the bytes that get fed
-- into `sha256(0x00 || canonical_bytes)` to produce `leaf_hash`).
-- `leaf_serialized` is the full serde-JSON serialization of the
-- AuditLeaf wrapper (including `chain_event_id` + the full
-- `AuditEntry`) so `TransparencyStore::get(index)` can round-trip the
-- leaf without joining back to `cirislens.audit_log`. Two columns is
-- cheap (audit entries are small) and keeps the Phase B store
-- self-contained per FSD §4.4 (the audit log is source-of-truth, but
-- the merkle layer round-trips its own leaves without depending on the
-- foreign-key target).

CREATE TABLE cirislens.merkle_leaves (
    tenant_id          TEXT NOT NULL,
    leaf_index         BIGINT NOT NULL,
    chain_event_id     BIGINT NOT NULL,
    leaf_hash          BYTEA NOT NULL,
    canonical_bytes    BYTEA NOT NULL,
    leaf_serialized    BYTEA NOT NULL,
    appended_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, leaf_index),
    UNIQUE (tenant_id, chain_event_id),
    CHECK (octet_length(leaf_hash) = 32)
);

CREATE INDEX idx_merkle_leaves_chain ON cirislens.merkle_leaves (chain_event_id);

-- ─── merkle_sth_log ────────────────────────────────────────────────
--
-- `signature_blob` carries the serde-JSON serialization of
-- `ciris_crypto::HybridSignature` (crypto_kind + tagged classical +
-- tagged PQC + mode). The tagged structure carries algorithm + public
-- key info that bare `signature_classical` + `signature_pqc` BYTEA
-- columns would lose. Storage is JSON-as-BYTEA (vs JSONB) so SQLite
-- parity stays straightforward — both dialects round-trip identical
-- bytes via `serde_json::to_vec` / `serde_json::from_slice`.

CREATE TABLE cirislens.merkle_sth_log (
    tenant_id              TEXT NOT NULL,
    tree_size              BIGINT NOT NULL,
    root_hash              BYTEA NOT NULL,
    signed_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    signer_key_id          TEXT NOT NULL,
    signature_blob         BYTEA NOT NULL,
    witness_signatures     JSONB NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (tenant_id, tree_size),
    CHECK (octet_length(root_hash) = 32)
);

CREATE INDEX idx_merkle_sth_signed_at ON cirislens.merkle_sth_log (tenant_id, signed_at DESC);
