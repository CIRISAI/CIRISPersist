-- V021 — Federation trust grants + per-tenant Merkle layer, SQLite
-- dialect (v1.5.0 Phase A, FEDERATION_TRUST_INTERFACE.md §2 + §4.4).
--
-- Postgres parity (postgres/lens/V021): same column shapes + tables.
-- See that file's header for the architectural rationale.
--
-- # Dialect notes
--
-- * **UUID** → **TEXT**. Callers (Engine.grant_trust, projector) MUST
--   generate UUIDs in Rust via `Uuid::new_v4()` before INSERT; no
--   `gen_random_uuid()` equivalent in SQLite (matches V020 dialect
--   pattern).
-- * **BYTEA** → **BLOB**. SQLite native binary type.
-- * **TIMESTAMPTZ** → **TEXT** (RFC 3339 string via
--   `chrono::DateTime::to_rfc3339`). Lexical comparison works when
--   offsets are normalized to `Z`, which persist always emits.
--   Matches V001 / V020 SQLite convention.
-- * **JSONB** → **TEXT** (JSON string). `witness_signatures` carries
--   the same data, just text-encoded; bind via
--   `serde_json::to_string`.
-- * **CURRENT_TIMESTAMP** default emits `YYYY-MM-DD HH:MM:SS` without
--   the `T` separator or `Z` suffix — RFC 3339-lite. The audit chain
--   pattern (V001) accepts it; future readers MUST normalize via
--   `chrono::DateTime::parse_from_rfc3339` / `parse_from_str`.
--
-- # Refinery transaction wrapping
--
-- Refinery wraps each migration in its own transaction. NO explicit
-- BEGIN/COMMIT.

-- ─── federation_trust_grants ───────────────────────────────────────

CREATE TABLE federation_trust_grants (
    grant_id           TEXT PRIMARY KEY,    -- UUID-as-TEXT; caller generates
    grantee_key        TEXT NOT NULL REFERENCES federation_keys(key_id),
    granter_key        TEXT NOT NULL REFERENCES federation_keys(key_id),
    purpose            TEXT NOT NULL
                       CHECK (purpose IN ('technical','deferral','contribution','service')),
    scope              TEXT NOT NULL,
    granted_at         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at         TEXT,
    revoked_at         TEXT,
    revoked_by         TEXT REFERENCES federation_keys(key_id),
    chain_event_id     INTEGER NOT NULL,
    chain_event_hash   BLOB NOT NULL,
    tenant_id          TEXT NOT NULL,
    CHECK (granter_key != grantee_key),
    CHECK (revoked_at IS NULL OR revoked_by IS NOT NULL),
    UNIQUE (grantee_key, granter_key, purpose, scope)
);

CREATE INDEX idx_ftg_grantee_purpose ON federation_trust_grants
    (grantee_key, purpose, scope) WHERE revoked_at IS NULL;
CREATE INDEX idx_ftg_granter ON federation_trust_grants (granter_key);
CREATE INDEX idx_ftg_chain ON federation_trust_grants (chain_event_id);
CREATE INDEX idx_ftg_tenant ON federation_trust_grants (tenant_id);

-- ─── merkle_leaves ─────────────────────────────────────────────────

CREATE TABLE merkle_leaves (
    tenant_id          TEXT NOT NULL,
    leaf_index         INTEGER NOT NULL,
    chain_event_id     INTEGER NOT NULL,
    leaf_hash          BLOB NOT NULL,
    canonical_bytes    BLOB NOT NULL,
    appended_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, leaf_index),
    UNIQUE (tenant_id, chain_event_id),
    CHECK (length(leaf_hash) = 32)
);

CREATE INDEX idx_merkle_leaves_chain ON merkle_leaves (chain_event_id);

-- ─── merkle_sth_log ────────────────────────────────────────────────

CREATE TABLE merkle_sth_log (
    tenant_id              TEXT NOT NULL,
    tree_size              INTEGER NOT NULL,
    root_hash              BLOB NOT NULL,
    signed_at              TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    signer_key_id          TEXT NOT NULL,
    signature_classical    BLOB NOT NULL,
    signature_pqc          BLOB,
    witness_signatures     TEXT NOT NULL DEFAULT '[]',  -- JSON-array string
    PRIMARY KEY (tenant_id, tree_size),
    CHECK (length(root_hash) = 32)
);

CREATE INDEX idx_merkle_sth_signed_at ON merkle_sth_log (tenant_id, signed_at DESC);
