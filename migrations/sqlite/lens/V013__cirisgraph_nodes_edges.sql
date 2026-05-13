-- V013 — cirisgraph schema, SQLite dialect (v0.8.4, CIRISPersist#38).
--
-- Postgres parity (V013 in postgres/lens): same column shapes, same
-- AV-45/46/47/48 semantics. Dialect translations:
--
--   PostgreSQL                      → SQLite
--   ─────────────────────────────────────────────────────────────────
--   JSONB                           → TEXT (canonical JSON; rusqlite
--                                          serde_json::Value via TEXT)
--   UUID                            → TEXT (36-char hyphenated form)
--   TIMESTAMPTZ                     → TEXT (RFC 3339 via chrono)
--   GIN on attributes               → expression index on
--                                          json_extract paths the
--                                          consumer actually filters
--   BYTEA                           → BLOB
--   NOW()                           → datetime('now', 'subsec')
--   PRIMARY KEY (text, text)        → PRIMARY KEY (text, text)
--                                          (same composite-key
--                                          semantics)
--
-- SQLite has no separate "schema" namespace — tables go in the
-- single attached DB; we keep them prefix-named for portability
-- between dialects ("cirisgraph_nodes" / "cirisgraph_edges").
--
-- # Recursive CTE for k-hop
--
-- SQLite 3.8.3+ supports `WITH RECURSIVE`; the v0.8.0 Postgres
-- impl's CTE shape works almost verbatim — only `text[]`
-- parameter binding changes (rusqlite doesn't natively bind
-- text[]; the impl serializes the relationship allow-list as a
-- comma-separated single TEXT param and uses a SQLite
-- json_each() join).

CREATE TABLE IF NOT EXISTS cirisgraph_nodes (
    node_id          TEXT NOT NULL,
    scope            TEXT NOT NULL
        CHECK (scope IN ('LOCAL', 'IDENTITY', 'ENVIRONMENT', 'COMMUNITY')),
    node_type        TEXT NOT NULL,
    attributes       TEXT NOT NULL,
    version          INTEGER NOT NULL DEFAULT 1
        CHECK (version >= 1),
    updated_by       TEXT NOT NULL,
    updated_at       TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    created_at       TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),

    -- Audit envelope.
    signature                 TEXT,
    signing_key_id            TEXT,
    signature_verified        INTEGER NOT NULL DEFAULT 0,
    original_content_hash     BLOB,
    persist_row_hash          TEXT,

    PRIMARY KEY (node_id, scope)
);

CREATE INDEX IF NOT EXISTS cirisgraph_nodes_type_scope
    ON cirisgraph_nodes (node_type, scope);

CREATE INDEX IF NOT EXISTS cirisgraph_nodes_updated_at
    ON cirisgraph_nodes (updated_at);

CREATE TABLE IF NOT EXISTS cirisgraph_edges (
    edge_id          TEXT PRIMARY KEY,
    source_node_id   TEXT NOT NULL,
    target_node_id   TEXT NOT NULL,
    scope            TEXT NOT NULL
        CHECK (scope IN ('LOCAL', 'IDENTITY', 'ENVIRONMENT', 'COMMUNITY')),
    relationship     TEXT NOT NULL,
    weight           REAL,
    attributes       TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);

CREATE INDEX IF NOT EXISTS cirisgraph_edges_source
    ON cirisgraph_edges (source_node_id, scope);
CREATE INDEX IF NOT EXISTS cirisgraph_edges_target
    ON cirisgraph_edges (target_node_id, scope);
CREATE INDEX IF NOT EXISTS cirisgraph_edges_relationship
    ON cirisgraph_edges (relationship);
