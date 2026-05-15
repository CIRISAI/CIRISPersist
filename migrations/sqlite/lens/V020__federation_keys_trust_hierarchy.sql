-- V020 — Federation trust hierarchy + roles + edge detection events,
-- SQLite dialect (v1.3.0, CIRISPersist#46 + #47).
--
-- Postgres parity (postgres/lens/V020): same column shapes + table +
-- audit vocabulary extension. See that file's header for the
-- architectural rationale.
--
-- # Dialect notes
--
-- * **TEXT[]** → **TEXT** holding a JSON-array string. Bind via
--   `serde_json::to_string(&domains)`; query via `json_each`. The
--   PG `array_length(...) > 0` check on Registry rows is enforced
--   at the API surface (`FederationDirectory::grant_trust` /
--   `revoke_trust`) — SQLite ALTER TABLE can't ADD CHECK.
-- * **TIMESTAMPTZ** → **TEXT** (RFC 3339). Lexical comparison works
--   when offsets are normalized to `Z`, which persist always emits
--   via `chrono::DateTime::to_rfc3339`.
-- * **UUID** → **TEXT**. Callers generate UUIDs in Rust before
--   INSERT (mirroring the V004 SQLite pattern).
-- * **`trusted_by != key_id`** rule: SQLite's ALTER TABLE ADD COLUMN
--   accepts NOT NULL + DEFAULT but NOT a CHECK clause. The
--   inequality is enforced at the API surface
--   (`FederationDirectory::grant_trust`) — matches the V019 +
--   v1.1.0 #46 pattern documented elsewhere in this migration tree.
-- * **gen_random_uuid()** has no SQLite equivalent; the API surface
--   generates UUIDs before INSERT.
-- * **GIN index on trust_domains** → no SQLite equivalent. Filtering
--   on domain membership runs at query time via `json_each` (the
--   SQLite impl's `list_trusted_keys` joins the JSON array).
-- * **audit_log CHECK extension** → SQLite doesn't have one to
--   replace. The V018 PG CHECK was a PG-only deployment add per
--   V018's header note "SQLite enforcement is convention-only for
--   v1.0.0 (the table rebuild required for `ALTER TABLE ADD CHECK`
--   is deferred)". V020 maintains that convention: the trust_granted
--   + trust_revoked tokens are valid in SQLite by application
--   contract; the `AuditEventType` enum is the single source of
--   truth.

-- ─── federation_keys: trust hierarchy ──────────────────────────────

ALTER TABLE federation_keys ADD COLUMN consent_role TEXT NOT NULL DEFAULT 'unregistered';
ALTER TABLE federation_keys ADD COLUMN trust_type TEXT NOT NULL DEFAULT 'temporary';
ALTER TABLE federation_keys ADD COLUMN trust_relationship TEXT NOT NULL DEFAULT 'direct';
ALTER TABLE federation_keys ADD COLUMN trust_domains TEXT;
ALTER TABLE federation_keys ADD COLUMN trusted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE federation_keys ADD COLUMN trusted_by TEXT;
ALTER TABLE federation_keys ADD COLUMN expires_at TEXT;

-- ─── federation_keys: per-row role tags (CIRISPersist#46) ──────────

-- JSON-array string holding the roles list. NULL = no roles (legacy
-- rows pre-V020 + new rows that didn't declare any). Empty array
-- `"[]"` is also legal.
ALTER TABLE federation_keys ADD COLUMN roles TEXT;

-- ─── Indexes for resolver queries ──────────────────────────────────

CREATE INDEX IF NOT EXISTS federation_keys_trust_relationship
    ON federation_keys (trust_relationship);

CREATE INDEX IF NOT EXISTS federation_keys_expires_at
    ON federation_keys (expires_at);

-- ─── edge_detection_events (LensCore detector signals) ─────────────

CREATE TABLE IF NOT EXISTS edge_detection_events (
    detection_id        TEXT PRIMARY KEY,  -- UUID-as-TEXT; caller generates
    tenant_id           TEXT NOT NULL,
    detector_kind       TEXT NOT NULL,
    -- FK to federation_keys.key_id — SQLite enforces with PRAGMA
    -- foreign_keys=ON which SqliteBackend boot pragmas already set.
    subject_key_id      TEXT NOT NULL REFERENCES federation_keys(key_id),
    observed_at         TEXT NOT NULL,
    evidence            TEXT NOT NULL,      -- JSONB → TEXT
    severity            TEXT NOT NULL,
    signature           TEXT NOT NULL,
    signing_key_id      TEXT NOT NULL,
    signature_verified  INTEGER NOT NULL DEFAULT 0,
    persist_row_hash    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS edge_detection_events_tenant_observed
    ON edge_detection_events (tenant_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS edge_detection_events_subject
    ON edge_detection_events (subject_key_id);
CREATE INDEX IF NOT EXISTS edge_detection_events_kind_severity
    ON edge_detection_events (detector_kind, severity);
