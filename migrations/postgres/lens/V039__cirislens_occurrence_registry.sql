-- V039 — occurrence registration + liveness heartbeat
-- (v1.7.3, CIRISPersist#81).
--
-- One row per live occurrence. `expires_at` is TTL-based: a crashed
-- occurrence ages out without a clean deregister. list_live_occurrences
-- filters `expires_at > NOW()`. All occurrences of one agent share a
-- single Ed25519 `identity` (PoB §3.2 one-key model) — this table is
-- endpoint liveness under that stable identity, not membership change.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT.

CREATE TABLE cirislens.occurrence_registry (
    occurrence_id   TEXT PRIMARY KEY,
    identity        TEXT NOT NULL,
    registered_at   TIMESTAMPTZ NOT NULL,
    last_heartbeat  TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    metadata        JSONB
);

CREATE INDEX occurrence_registry_identity_live
    ON cirislens.occurrence_registry (identity, expires_at);

COMMENT ON TABLE cirislens.occurrence_registry IS
    'v1.7.3 (CIRISPersist#81) — occurrence liveness registry. TTL-based: expires_at > NOW() means live. Crashed occurrences age out.';
