-- V030 — maintenance_locks substrate (v1.5.15, CIRISPersist#59 #7).
--
-- SQLite mirror of V030 PG. Dialect translations:
--   TIMESTAMPTZ                → TEXT (RFC 3339)
--   JSONB                      → TEXT (raw JSON string)
--   Partial index predicate    → unchanged (SQLite supports
--                                partial indexes since 3.8)
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens_maintenance_locks (
    lock_key             TEXT PRIMARY KEY,
    locked_by            TEXT,
    locked_at            TEXT,
    lock_timeout_seconds INTEGER NOT NULL DEFAULT 300
        CHECK (lock_timeout_seconds > 0),
    metadata             TEXT
);

CREATE INDEX maintenance_locks_active
    ON cirislens_maintenance_locks (locked_at DESC)
    WHERE locked_by IS NOT NULL;
