-- V013 — cirisgraph schema: node + edge tables (v0.8.0, CIRISPersist#34).
--
-- Closes the substrate-readiness gap for CIRISAgent's Phase 1B
-- migration. Absorbs LocalGraphMemoryService + GraphConfigService
-- off the agent's homegrown SQLite/Postgres + hand-rolled SQL.
--
-- # Why Postgres + recursive CTEs (no embedded graph DB engine)
--
-- Verified via deepwiki against CIRISAgent's live code: the actual
-- graph workload is point lookup + time-window scan + bounded
-- procedural k-hop. NO Cypher/Datalog requirement. Pulling in
-- CozoDB / kuzu / indradb would add an embedded DB engine + separate
-- backup/ops story + Rust dep weight for ZERO query expressiveness
-- gain. Postgres recursive CTE on (node, edge) tables with a GIN
-- index on JSONB attributes handles every observed pattern at
-- substrate-grade reliability.
--
-- # Schema parity with CIRISAgent
--
-- Column shapes mirror the agent's existing schema (node_id, scope,
-- node_type, attributes_json, version, updated_by, updated_at,
-- created_at) so the Phase 1B cutover can read agent-written rows
-- via a one-shot ETL without shape translation. Audit-envelope
-- columns are persist-side additions — agent writes set them via
-- the new Rust API; legacy rows leave them NULL.

BEGIN;

CREATE SCHEMA IF NOT EXISTS cirisgraph;

-- ── nodes — typed graph nodes with JSONB attributes ─────────────

CREATE TABLE IF NOT EXISTS cirisgraph.nodes (
    -- Caller-supplied identifier (matches agent convention: not a
    -- UUID — agent uses semantic IDs like "agent:datum-v3-default"
    -- or "channel:discord-123-456789").
    node_id          TEXT NOT NULL,

    -- GraphScope: LOCAL = process-local; IDENTITY = agent self-
    -- knowledge; ENVIRONMENT = ambient platform / channel context;
    -- COMMUNITY = federation-shared knowledge. AV-47: every read
    -- pins this in WHERE; type system requires it at the trait.
    scope            TEXT NOT NULL
        CHECK (scope IN ('LOCAL', 'IDENTITY', 'ENVIRONMENT', 'COMMUNITY')),

    -- Free-form type label — `agent`, `user`, `channel`, `config`,
    -- `tsdb_data`, `tsdb_summary`, etc. Agent owns the taxonomy;
    -- persist enforces it stays TEXT (not enum) so the agent can
    -- add types without schema migrations.
    node_type        TEXT NOT NULL,

    -- Versioned attributes blob. AV-45: per-call size cap enforced
    -- at the trait layer (default 1 MiB); GIN index here gives
    -- predicate-push-down for attribute filters.
    attributes       JSONB NOT NULL,

    -- AV-48: UPSERT replay safety — caller passes expected_version;
    -- mismatch → Conflict. Starts at 1; increments on every
    -- successful upsert.
    version          INTEGER NOT NULL DEFAULT 1
        CHECK (version >= 1),

    -- Lifecycle.
    updated_by       TEXT NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Audit envelope (matches V004 / V011 shape — Ed25519 signed by
    -- the writer over canonical(node minus signature)).
    signature                 TEXT,
    signing_key_id            TEXT,
    signature_verified        BOOLEAN NOT NULL DEFAULT FALSE,
    original_content_hash     BYTEA,
    persist_row_hash          TEXT,

    PRIMARY KEY (node_id, scope)
);

-- Type + scope: hot path for "all CONFIG nodes in IDENTITY scope".
CREATE INDEX IF NOT EXISTS nodes_type_scope
    ON cirisgraph.nodes (node_type, scope);

-- Time-window scans (TSDB consolidation + recent-write reads).
CREATE INDEX IF NOT EXISTS nodes_updated_at
    ON cirisgraph.nodes (updated_at);

-- Attribute predicate push-down. GIN on the whole JSONB column;
-- caller queries via @> containment or ? key existence.
CREATE INDEX IF NOT EXISTS nodes_attributes_gin
    ON cirisgraph.nodes USING GIN (attributes);

COMMENT ON TABLE cirisgraph.nodes IS
    'v0.8.0 (CIRISPersist#34) — typed graph nodes absorbed from CIRISAgent LocalGraphMemoryService. Schema mirrors agent column shape for parity; persist adds audit envelope (signature / signing_key_id / signature_verified / original_content_hash / persist_row_hash). PK is (node_id, scope) — same id may exist in multiple scopes without collision.';

-- ── edges — typed relationships between nodes ───────────────────

CREATE TABLE IF NOT EXISTS cirisgraph.edges (
    edge_id          UUID PRIMARY KEY,
    source_node_id   TEXT NOT NULL,
    target_node_id   TEXT NOT NULL,
    scope            TEXT NOT NULL
        CHECK (scope IN ('LOCAL', 'IDENTITY', 'ENVIRONMENT', 'COMMUNITY')),

    -- Relationship label — SUMMARIZES / TEMPORAL_NEXT / TEMPORAL_PREV
    -- (TSDB), OWNS / HAS_MEMBER (config trees), etc. Agent owns the
    -- vocabulary.
    relationship     TEXT NOT NULL,

    -- Optional weight (e.g. similarity score, decay coefficient).
    weight           DOUBLE PRECISION,

    -- Per-edge attributes (e.g. timestamp window for SUMMARIZES,
    -- direction for TEMPORAL_*).
    attributes       JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()

    -- NOTE: no FK on (source_node_id, scope) / (target_node_id, scope)
    -- — the agent's existing schema permits edges that reference
    -- nodes not yet inserted (eventual-consistency writes during
    -- batch ingest). The k-hop traversal CTE in v0.8.0 PG impl
    -- naturally tolerates dangling edges (LEFT JOIN), and the agent's
    -- write order is already correct in steady state.
);

-- Per-direction lookup: "all edges FROM this node" / "all edges TO".
CREATE INDEX IF NOT EXISTS edges_source
    ON cirisgraph.edges (source_node_id, scope);
CREATE INDEX IF NOT EXISTS edges_target
    ON cirisgraph.edges (target_node_id, scope);

-- Relationship-typed filter: "all SUMMARIZES edges for window X".
CREATE INDEX IF NOT EXISTS edges_relationship
    ON cirisgraph.edges (relationship);

COMMENT ON TABLE cirisgraph.edges IS
    'v0.8.0 (CIRISPersist#34) — directed typed edges between nodes. No FK on source/target so eventual-consistency writes work; k-hop CTE tolerates dangling edges. (edge_id) is the PK (UUID); the (source, target, relationship) tuple may repeat across different windows / weights.';

COMMIT;
