-- V004 — Federation directory schema (v0.2.0, SQLite).
--
-- SQLite translation of migrations/postgres/lens/V004__federation_directory.sql.
-- See that file's header for architectural rationale and the registry
-- alignment context.
--
-- Type translations (continuity with V001 sqlite migration):
--   TEXT             stays TEXT
--   TIMESTAMPTZ      → TEXT (RFC 3339; lexical comparison works for UTC)
--   JSONB            → TEXT (SQLite has json1 extension for queries
--                            but stores as TEXT — same as the payload
--                            column on V001 trace_events)
--   BYTEA            → BLOB (SQLite native; rusqlite handles it)
--   NUMERIC          → REAL (SQLite has no fixed-point)
--   UUID             → TEXT (SQLite has no UUID type; rusqlite passes
--                            UUID strings as TEXT)
--   gen_random_uuid() → no SQLite equivalent; consumers generate UUID
--                       in Rust before INSERT (see SqliteBackend impl)
--   CREATE SCHEMA cirislens → dropped; SQLite has no schemas
--   FOREIGN KEY ... DEFERRABLE → SQLite supports DEFERRABLE INITIALLY
--                                DEFERRED with PRAGMA foreign_keys=ON
--                                (which the SqliteBackend boot pragmas
--                                enable already)

-- ─── federation_keys ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS federation_keys (
    key_id                TEXT PRIMARY KEY,
    pubkey_base64         TEXT NOT NULL,
    algorithm             TEXT NOT NULL,
    identity_type         TEXT NOT NULL,
    identity_ref          TEXT NOT NULL,
    valid_from            TEXT NOT NULL,
    valid_until           TEXT,
    registration_envelope TEXT NOT NULL,

    original_content_hash BLOB NOT NULL,
    scrub_signature       BLOB NOT NULL,
    scrub_key_id          TEXT NOT NULL,
    scrub_timestamp       TEXT NOT NULL,

    persist_row_hash      TEXT NOT NULL,

    -- DEFERRABLE INITIALLY DEFERRED so the bootstrap (self-signed)
    -- row INSERT doesn't violate the FK at row-write time. Constraint
    -- checked at COMMIT.
    FOREIGN KEY (scrub_key_id) REFERENCES federation_keys(key_id) DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX IF NOT EXISTS federation_keys_identity
    ON federation_keys (identity_type, identity_ref);
CREATE INDEX IF NOT EXISTS federation_keys_scrub_key
    ON federation_keys (scrub_key_id);

-- ─── federation_attestations ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS federation_attestations (
    attestation_id        TEXT PRIMARY KEY,  -- UUID-as-TEXT; caller generates
    attesting_key_id      TEXT NOT NULL REFERENCES federation_keys(key_id),
    attested_key_id       TEXT NOT NULL REFERENCES federation_keys(key_id),
    attestation_type      TEXT NOT NULL,
    weight                REAL,
    asserted_at           TEXT NOT NULL,
    expires_at            TEXT,
    attestation_envelope  TEXT NOT NULL,

    original_content_hash BLOB NOT NULL,
    scrub_signature       BLOB NOT NULL,
    scrub_key_id          TEXT NOT NULL REFERENCES federation_keys(key_id),
    scrub_timestamp       TEXT NOT NULL,

    persist_row_hash      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS federation_attestations_attested
    ON federation_attestations (attested_key_id, asserted_at DESC);
CREATE INDEX IF NOT EXISTS federation_attestations_attesting
    ON federation_attestations (attesting_key_id, asserted_at DESC);

-- ─── federation_revocations ────────────────────────────────────────

CREATE TABLE IF NOT EXISTS federation_revocations (
    revocation_id         TEXT PRIMARY KEY,  -- UUID-as-TEXT
    revoked_key_id        TEXT NOT NULL REFERENCES federation_keys(key_id),
    revoking_key_id       TEXT NOT NULL REFERENCES federation_keys(key_id),
    reason                TEXT,
    revoked_at            TEXT NOT NULL,
    effective_at          TEXT NOT NULL,
    revocation_envelope   TEXT NOT NULL,

    original_content_hash BLOB NOT NULL,
    scrub_signature       BLOB NOT NULL,
    scrub_key_id          TEXT NOT NULL REFERENCES federation_keys(key_id),
    scrub_timestamp       TEXT NOT NULL,

    persist_row_hash      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS federation_revocations_revoked
    ON federation_revocations (revoked_key_id, effective_at DESC);
