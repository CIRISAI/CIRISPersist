-- V059 — CEG 0.7 §5.6.8.8 + §5.6.8.9 identity_occurrence + family —
--        SQLite dialect (CIRISPersist#153 Asks 1-2, v3.12.0).
--
-- Postgres parity: postgres/lens/V059. See that file for the full
-- design rationale (identity_occurrence as "participants that ARE me"
-- vs family as "trusted nodes that compose with me"; the at-rest DEK
-- cascade gating; the structural lock on consensus_protocol amendment).
--
-- This cut lands schema foundation + value-validation admission;
-- trust-graph admission (vouch chains, consensus_protocol signature
-- counting, retroactive key_grant emission) is the v3.13+ work.

-- ─── §5.6.8.8 federation_identity_occurrences ──────────────────────
--
-- TIMESTAMPTZ → TEXT (ISO-8601, the project's universal time encoding).

CREATE TABLE IF NOT EXISTS federation_identity_occurrences (
    identity_key_id       TEXT NOT NULL
        REFERENCES federation_keys(key_id),
    occurrence_key_id     TEXT NOT NULL
        REFERENCES federation_keys(key_id),

    device_class          TEXT NOT NULL
        CHECK (device_class IN ('phone', 'laptop', 'server', 'embedded',
                                 'agent', 'service')),

    hardware_attestation  TEXT,

    asserted_at           TEXT NOT NULL,
    valid_until           TEXT,

    persist_row_hash      TEXT NOT NULL,

    PRIMARY KEY (identity_key_id, occurrence_key_id)
);

CREATE INDEX IF NOT EXISTS federation_identity_occurrences_by_identity
    ON federation_identity_occurrences (identity_key_id);

-- Live-only partial index. SQLite can't reference NOW() in a partial
-- index predicate (no built-in matching the postgres `NOW()` shape
-- usable as immutable), so the partial uses a simple `valid_until IS
-- NULL` arm — the most common case (indefinite occurrence). Expired
-- rows still get scanned via the full-table fallback when needed.
CREATE INDEX IF NOT EXISTS federation_identity_occurrences_by_occurrence_live
    ON federation_identity_occurrences (occurrence_key_id)
    WHERE valid_until IS NULL;

CREATE INDEX IF NOT EXISTS federation_identity_occurrences_by_occurrence_all
    ON federation_identity_occurrences (occurrence_key_id);

-- ─── §5.6.8.9 federation_families ──────────────────────────────────
--
-- members stored as JSON TEXT (SQLite's json1 extension parses on
-- demand via json_extract). Postgres uses JSONB native; sqlite parses
-- on the read path.

CREATE TABLE IF NOT EXISTS federation_families (
    family_key_id                   TEXT PRIMARY KEY
        REFERENCES federation_keys(key_id),

    family_name                     TEXT NOT NULL,

    members                         TEXT NOT NULL DEFAULT '[]'
        CHECK (json_type(members) = 'array'),

    founded_at                      TEXT NOT NULL,

    consensus_protocol              TEXT NOT NULL,

    consensus_protocol_entrenched   INTEGER NOT NULL DEFAULT 0
        CHECK (consensus_protocol_entrenched IN (0, 1)),

    persist_row_hash                TEXT NOT NULL
);

-- Entrenched-protocol partial index (small set; §9 HUMANITY_ACCORD-
-- style lookup).
CREATE INDEX IF NOT EXISTS federation_families_entrenched
    ON federation_families (family_key_id)
    WHERE consensus_protocol_entrenched = 1;
