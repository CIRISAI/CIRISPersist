-- V010 — federated SecretsService schema, SQLite dialect (v0.9.3, #38).
--
-- Postgres parity (postgres/lens/V010): same 5 tables, same audit
-- envelope shape, same AES-256-GCM + PBKDF2 crypto facade routing
-- (dialect-agnostic — the crypto path runs through ciris-crypto, not
-- via DB calls).
--
-- Dialect translations:
--
--   PostgreSQL                       → SQLite
--   ─────────────────────────────────────────────────────────────────
--   UUID                             → TEXT (36-char hyphenated)
--   BYTEA (ciphertext, salt, nonce)  → BLOB
--   TEXT[] auto_decapsulate          → TEXT (JSON array string)
--   JSONB config_value               → TEXT (canonical JSON)
--   TIMESTAMPTZ                      → TEXT (RFC 3339)
--   BIGSERIAL log_id PRIMARY KEY     → INTEGER PRIMARY KEY AUTOINCREMENT
--   FK self-reference                → REFERENCES (same syntax)
--   Partial index ON cond            → CREATE INDEX … WHERE (same)
--   NOW()                            → datetime('now', 'subsec')
--
-- SQLite has no separate schema namespace — tables go in the
-- single attached DB, prefixed `cirislens_secrets_*` to match the
-- v0.6.1 / v0.8.x naming convention.

-- ── secrets — encrypted-payload store ─────────────────────────────

CREATE TABLE IF NOT EXISTS cirislens_secrets_secrets (
    secret_uuid                   TEXT PRIMARY KEY,
    encrypted_value               BLOB NOT NULL,
    encryption_key_ref            TEXT NOT NULL,
    salt                          BLOB NOT NULL,
    nonce                         BLOB NOT NULL,
    description                   TEXT NOT NULL,
    sensitivity_level             TEXT NOT NULL
        CHECK (sensitivity_level IN ('low','medium','high','critical')),
    detected_pattern              TEXT NOT NULL,
    context_hint                  TEXT,
    created_at                    TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    last_accessed                 TEXT,
    access_count                  INTEGER NOT NULL DEFAULT 0,
    source_message_id             TEXT,
    auto_decapsulate_for_actions  TEXT NOT NULL DEFAULT '[]',
    manual_access_only            INTEGER NOT NULL DEFAULT 0,
    record_schema_version         TEXT NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS secrets_created_at
    ON cirislens_secrets_secrets (created_at);
CREATE INDEX IF NOT EXISTS secrets_sensitivity
    ON cirislens_secrets_secrets (sensitivity_level);
CREATE INDEX IF NOT EXISTS secrets_pattern
    ON cirislens_secrets_secrets (detected_pattern);
CREATE INDEX IF NOT EXISTS secrets_source_message
    ON cirislens_secrets_secrets (source_message_id)
    WHERE source_message_id IS NOT NULL;

-- ── access_log — auditable access trail ──────────────────────────

CREATE TABLE IF NOT EXISTS cirislens_secrets_access_log (
    log_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_uuid   TEXT,
    accessor      TEXT NOT NULL,
    operation     TEXT NOT NULL
        CHECK (operation IN (
            'store','retrieve','recall','forget',
            'encrypt','decrypt','reencrypt','rotate'
        )),
    action_type   TEXT,
    purpose       TEXT,
    success       INTEGER NOT NULL,
    error         TEXT,
    trace_id      TEXT,
    thought_id    TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);

CREATE INDEX IF NOT EXISTS access_log_secret_uuid
    ON cirislens_secrets_access_log (secret_uuid)
    WHERE secret_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS access_log_accessor
    ON cirislens_secrets_access_log (accessor);
CREATE INDEX IF NOT EXISTS access_log_created_at
    ON cirislens_secrets_access_log (created_at);
CREATE INDEX IF NOT EXISTS access_log_trace_id
    ON cirislens_secrets_access_log (trace_id)
    WHERE trace_id IS NOT NULL;

-- ── master_key_meta — master-key lifecycle ───────────────────────

CREATE TABLE IF NOT EXISTS cirislens_secrets_master_key_meta (
    key_ref       TEXT PRIMARY KEY,
    key_kind      TEXT NOT NULL CHECK (key_kind IN ('software','hardware')),
    descriptor    TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    activated_at  TEXT,
    deactivated_at TEXT,
    rotated_to    TEXT REFERENCES cirislens_secrets_master_key_meta(key_ref)
);

CREATE INDEX IF NOT EXISTS master_key_active
    ON cirislens_secrets_master_key_meta (activated_at)
    WHERE deactivated_at IS NULL;

-- ── filter_config — pattern catalog ──────────────────────────────

CREATE TABLE IF NOT EXISTS cirislens_secrets_filter_config (
    config_id     TEXT PRIMARY KEY,
    config_value  TEXT NOT NULL,
    version       INTEGER NOT NULL DEFAULT 1,
    updated_at    TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    updated_by    TEXT NOT NULL
);

-- ── pseudonyms — Pseudonymize mapping ────────────────────────────

CREATE TABLE IF NOT EXISTS cirislens_pseudonyms (
    original_hash  BLOB PRIMARY KEY,
    pseudonym      TEXT NOT NULL UNIQUE,
    class          TEXT NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);

CREATE INDEX IF NOT EXISTS cirislens_pseudonyms_class
    ON cirislens_pseudonyms (class);
