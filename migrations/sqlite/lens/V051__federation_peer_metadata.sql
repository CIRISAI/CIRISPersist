-- V051 — `federation_peer_metadata` sibling table, SQLite dialect
-- (v3.1.0, CIRISPersist#117).
--
-- Postgres parity (postgres/lens/V051): same column shapes, same
-- closed-set trust CHECK, same FK + partial-index discipline.
-- Dialect translations:
--
--   PostgreSQL                     → SQLite
--   ──────────────────────────────────────────────────────────────────
--   TIMESTAMPTZ                    → TEXT (RFC 3339)
--   JSONB policy_blob              → TEXT (json1 querying available)
--   REFERENCES cirislens.x         → REFERENCES x (no schema prefix)
--   NOW()                          → strftime('%Y-%m-%dT%H:%M:%fZ','now')
--   ON DELETE CASCADE              → identical syntax (with PRAGMA
--                                    foreign_keys=ON, already set in
--                                    the SqliteBackend boot pragmas)
--
-- SQLite supports CHECK constraints inline at CREATE TABLE time and
-- supports partial indexes (WHERE clause on CREATE INDEX), so both
-- the trust enum and the live-rows-only / non-NULL-alias indexes
-- translate without further restructuring.
--
-- See postgres/lens/V051 for the architectural rationale.

CREATE TABLE IF NOT EXISTS federation_peer_metadata (
    key_id              TEXT    NOT NULL PRIMARY KEY
        REFERENCES federation_keys(key_id) ON DELETE CASCADE,
    alias               TEXT,
    trust               TEXT    NOT NULL DEFAULT 'untrusted'
        CHECK (trust IN ('untrusted', 'trusted', 'restricted', 'blocked')),
    notes               TEXT,
    policy_blob         TEXT,
    transport_identity  TEXT,
    removed_at          TEXT,
    inserted_at         TEXT    NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at          TEXT    NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    persist_row_hash    TEXT    NOT NULL
);

-- "List my trusted peers" — partial index on live rows only.
CREATE INDEX IF NOT EXISTS idx_fpm_trust
    ON federation_peer_metadata (trust)
    WHERE removed_at IS NULL;

-- "Look this peer up by the alias I gave it" — partial index, NULL
-- aliases skipped.
CREATE INDEX IF NOT EXISTS idx_fpm_alias
    ON federation_peer_metadata (alias)
    WHERE alias IS NOT NULL;
