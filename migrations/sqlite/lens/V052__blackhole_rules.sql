-- V052 — `blackhole_rules` durable per-identity deny-list, SQLite
-- dialect (v3.2.0, CIRISPersist#120).
--
-- Postgres parity (postgres/lens/V052): same column shapes, same
-- partial-index discipline. Dialect translations:
--
--   PostgreSQL                     → SQLite
--   ──────────────────────────────────────────────────────────────────
--   BYTEA                          → BLOB
--   TIMESTAMPTZ                    → TEXT (RFC 3339)
--   NOW()                          → strftime('%Y-%m-%dT%H:%M:%fZ','now')
--   BIGINT                         → INTEGER (SQLite int is 64-bit)
--   schema prefix `cirislens.x`    → bare `x` (per-DB ABI)
--
-- SQLite supports `WHERE` clauses on `CREATE INDEX` (partial indexes),
-- so the `(until) WHERE until IS NOT NULL` shape translates without
-- restructuring. See postgres/lens/V052 for the architectural
-- rationale (sibling-table choice, no length CHECK, commutative
-- counter discipline).

CREATE TABLE IF NOT EXISTS blackhole_rules (
    identity_hash    BLOB    NOT NULL PRIMARY KEY,
    until            TEXT,
    reason           TEXT,
    added_at         TEXT    NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    hits             INTEGER NOT NULL DEFAULT 0,
    persist_row_hash TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blackhole_until
    ON blackhole_rules (until)
    WHERE until IS NOT NULL;
