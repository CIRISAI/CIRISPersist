-- V038 — atomic per-identity monotonic sequence, SQLite dialect
-- (v1.7.1, CIRISPersist#83). Postgres parity. TIMESTAMPTZ → TEXT.

CREATE TABLE cirislens_identity_sequences (
    identity    TEXT NOT NULL,
    stream      TEXT NOT NULL,
    next_value  INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (identity, stream)
);
