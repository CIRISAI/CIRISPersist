-- V111 (CIRISPersist#507b) — the shared signed-wire content-hash index.
-- Postgres dialect. SQLite parity: sqlite/lens/V111. See that file for the
-- full rationale.

CREATE TABLE cirislens.signed_wire_index (
    kind            TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    record_key      TEXT NOT NULL,
    PRIMARY KEY (kind, content_hash)
);
