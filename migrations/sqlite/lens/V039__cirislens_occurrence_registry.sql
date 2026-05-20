-- V039 — occurrence registry, SQLite dialect (v1.7.3, CIRISPersist#81).
-- Postgres parity. TIMESTAMPTZ → TEXT (RFC 3339); JSONB → TEXT.

CREATE TABLE cirislens_occurrence_registry (
    occurrence_id   TEXT PRIMARY KEY,
    identity        TEXT NOT NULL,
    registered_at   TEXT NOT NULL,
    last_heartbeat  TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    metadata        TEXT
);

CREATE INDEX occurrence_registry_identity_live
    ON cirislens_occurrence_registry (identity, expires_at);
