-- V010 — Federated SecretsService schema (v0.6.1, CIRISPersist#19).
--
-- Companion to FSD POST_INGEST_FILTER_PIPELINE.md §7.3. Persist
-- becomes the federation-stable host for the encrypted secrets store
-- that CIRISAgent's SecretsServiceProtocol absorbs (`secrets are on
-- us`).
--
-- # Tables
--
-- - cirislens_secrets.secrets               — encrypted-payload store
-- - cirislens_secrets.access_log            — auditable access trail
-- - cirislens_secrets.master_key_meta       — master-key lifecycle
-- - cirislens_secrets.filter_config         — pattern-catalog CRUD
-- - cirislens_pseudonyms                    — stable Pseudonymize mappings
--
-- All five tables NEW in v0.6.1. No interaction with V009 pipeline
-- columns; the secrets schema is orthogonal to the pipeline JSONB
-- on cirislens.trace_events.
--
-- # Crypto invariant
--
-- All encrypted_value blobs in cirislens_secrets.secrets are produced
-- by AES-256-GCM via `src/secrets/crypto.rs` (the sole import site of
-- ciris_crypto::aes_gcm). The schema records the salt + nonce
-- alongside the ciphertext, plus an `encryption_key_ref` pointing
-- into `master_key_meta`. Persist NEVER sees plaintext outside the
-- decapsulation hot path; consumers should treat the table as
-- write-after-encrypt, read-via-decapsulate.

BEGIN;

CREATE SCHEMA IF NOT EXISTS cirislens_secrets;

-- ── secrets — the encrypted-payload store ────────────────────────────

CREATE TABLE IF NOT EXISTS cirislens_secrets.secrets (
    -- Stable UUID; this is what `{SECRET:uuid:description}` placeholders
    -- and `recall_secret(uuid, ...)` reference.
    secret_uuid                   UUID PRIMARY KEY,

    -- AES-256-GCM ciphertext (auth tag appended per the GCM spec).
    encrypted_value               BYTEA NOT NULL,

    -- FK into cirislens_secrets.master_key_meta(key_ref). String form
    -- so we can route to TPM-backed keys later via the same column.
    encryption_key_ref            TEXT NOT NULL,

    -- Per-secret salt (PBKDF2 input). 32 bytes by convention; the
    -- crypto facade rejects non-32 lengths at insert time.
    salt                          BYTEA NOT NULL,

    -- AES-GCM nonce. 12 bytes per the GCM spec; crypto facade gates.
    nonce                         BYTEA NOT NULL,

    -- Human-readable description shown in `list_stored_secrets` +
    -- `recall_secret` metadata responses. NOT encrypted.
    description                   TEXT NOT NULL,

    -- Sensitivity level (controls auto_decapsulate_for_actions default).
    -- Matches CIRISAgent SensitivityLevel taxonomy.
    sensitivity_level             TEXT NOT NULL
        CHECK (sensitivity_level IN ('low','medium','high','critical')),

    -- Detected pattern id (e.g. "regex:api_key_v1", "regex:bearer_token").
    -- Stable across CIRIS deployments per FSD §6.3 matcher_id convention.
    detected_pattern              TEXT NOT NULL,

    -- Optional context hint (e.g. "found in tool_args.api_key").
    context_hint                  TEXT,

    -- Lifecycle timestamps.
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_accessed                 TIMESTAMPTZ,
    access_count                  BIGINT NOT NULL DEFAULT 0,

    -- Source-message linkage. Optional — direct `store_secret`
    -- (manual entry) leaves this NULL; `process_incoming_text`
    -- populates it.
    source_message_id             TEXT,

    -- Whitelist of action_type tokens that may auto-decapsulate this
    -- secret (default-mapped from sensitivity_level per FSD §3.3).
    auto_decapsulate_for_actions  TEXT[] NOT NULL DEFAULT '{}',

    -- Hard manual-access flag. When TRUE the secret is NEVER
    -- auto-decapsulated regardless of action whitelist.
    manual_access_only            BOOLEAN NOT NULL DEFAULT FALSE,

    -- Row-shape version. Bumped when the column set changes; consumers
    -- skip rows whose version they don't recognize.
    record_schema_version         TEXT NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS secrets_created_at        ON cirislens_secrets.secrets (created_at);
CREATE INDEX IF NOT EXISTS secrets_sensitivity       ON cirislens_secrets.secrets (sensitivity_level);
CREATE INDEX IF NOT EXISTS secrets_pattern           ON cirislens_secrets.secrets (detected_pattern);
CREATE INDEX IF NOT EXISTS secrets_source_message    ON cirislens_secrets.secrets (source_message_id)
    WHERE source_message_id IS NOT NULL;

COMMENT ON TABLE cirislens_secrets.secrets IS
    'v0.6.1 (CIRISPersist#19) — encrypted-secrets store. AES-256-GCM via src/secrets/crypto.rs facade. Federated SecretsServiceProtocol substrate.';

-- ── access_log — auditable access trail ──────────────────────────────

CREATE TABLE IF NOT EXISTS cirislens_secrets.access_log (
    log_id        BIGSERIAL PRIMARY KEY,

    -- NULL for direct encrypt/decrypt ops (no specific row referenced).
    secret_uuid   UUID,

    -- Who/what performed the operation. Stable string token from the
    -- caller (PyO3 caller / federation peer / agent handler id).
    accessor      TEXT NOT NULL,

    operation     TEXT NOT NULL
        CHECK (operation IN (
            'store','retrieve','recall','forget',
            'encrypt','decrypt','reencrypt','rotate'
        )),

    -- Action context (e.g. 'tool', 'speak', 'memorize') — populated on
    -- recall/decapsulate paths so audit reveals which agent action
    -- triggered each decryption.
    action_type   TEXT,

    -- Free-form purpose string supplied by the caller. Useful for
    -- post-hoc audit reconstruction.
    purpose       TEXT,

    success       BOOLEAN NOT NULL,
    error         TEXT,

    -- Optional cross-link into the trace_events corpus for end-to-end
    -- audit (which trace's processing triggered which secret access).
    trace_id      TEXT,
    thought_id    TEXT,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS access_log_secret_uuid ON cirislens_secrets.access_log (secret_uuid)
    WHERE secret_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS access_log_accessor    ON cirislens_secrets.access_log (accessor);
CREATE INDEX IF NOT EXISTS access_log_created_at  ON cirislens_secrets.access_log (created_at);
CREATE INDEX IF NOT EXISTS access_log_trace_id    ON cirislens_secrets.access_log (trace_id)
    WHERE trace_id IS NOT NULL;

COMMENT ON TABLE cirislens_secrets.access_log IS
    'v0.6.1 (CIRISPersist#19) — every SecretsService operation appends here. Audit trail for FSD §3.1 #15.';

-- ── master_key_meta — master-key lifecycle ──────────────────────────

CREATE TABLE IF NOT EXISTS cirislens_secrets.master_key_meta (
    -- Opaque key reference. Software keys: random UUID at generation
    -- time. Hardware keys: TPM/Keystore-supplied descriptor.
    key_ref       TEXT PRIMARY KEY,

    key_kind      TEXT NOT NULL CHECK (key_kind IN ('software','hardware')),

    -- For hardware keys: CIRISVerify storage descriptor (TPM handle,
    -- Keystore alias, etc.). For software keys: NULL.
    descriptor    TEXT,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- When this key became the active master. NULL = generated but
    -- not yet active (rotation staging).
    activated_at  TIMESTAMPTZ,

    -- When this key was retired (a new key took over). NULL = still
    -- active or never used.
    deactivated_at TIMESTAMPTZ,

    -- The key_ref this key was rotated INTO. NULL for the current
    -- active key + for keys that were never active.
    rotated_to    TEXT REFERENCES cirislens_secrets.master_key_meta(key_ref)
);

-- Partial index for the current active key — the per-secret encrypt
-- path looks this up on every store.
CREATE INDEX IF NOT EXISTS master_key_active ON cirislens_secrets.master_key_meta (activated_at)
    WHERE deactivated_at IS NULL;

COMMENT ON TABLE cirislens_secrets.master_key_meta IS
    'v0.6.1 (CIRISPersist#19) — master-key lifecycle. rotate_master_key INSERTS a new row; reencrypt_all activates it; old key gets deactivated_at + rotated_to set.';

-- ── filter_config — pattern catalog CRUD ────────────────────────────

CREATE TABLE IF NOT EXISTS cirislens_secrets.filter_config (
    -- 'global' or per-deployment id. PRIMARY-KEYED so update_filter_config
    -- writes versioned rows.
    config_id     TEXT PRIMARY KEY,

    -- JSONB-serialized FilterConfig (see src/secrets/types.rs).
    config_value  JSONB NOT NULL,

    version       INTEGER NOT NULL DEFAULT 1,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by    TEXT NOT NULL
);

COMMENT ON TABLE cirislens_secrets.filter_config IS
    'v0.6.1 (CIRISPersist#19) — pattern-catalog config. CIRISAgent FilterConfig surface CRUD lives here per FSD §3.1 #11.';

-- ── cirislens_pseudonyms — Pseudonymize mapping ─────────────────────

CREATE TABLE IF NOT EXISTS cirislens_pseudonyms (
    -- SHA-256 of the original identifier (stable across hashes).
    original_hash  BYTEA PRIMARY KEY,

    -- Human-friendly pseudonym (e.g. "msg_a3f9", "user_b21e").
    pseudonym      TEXT NOT NULL UNIQUE,

    -- ContentClass kind from the FSD §6.3 taxonomy (UserId / MessageId
    -- / ChannelId / etc.) — controls which mapping pool each kind
    -- of identifier draws from.
    class          TEXT NOT NULL,

    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS cirislens_pseudonyms_class ON cirislens_pseudonyms (class);

COMMENT ON TABLE cirislens_pseudonyms IS
    'v0.6.1 (CIRISPersist#19) — stable Pseudonymize mappings for Action::Pseudonymize. Same hash → same pseudonym across federation peers.';

COMMIT;
