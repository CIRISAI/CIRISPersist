-- V133: the `registry_key_escrows` consumer-table family (CIRISPersist#752).
-- SQLite twin of migrations/postgres/lens/V133__registry_key_escrows.sql —
-- same columns, same nullability, same index names.
-- Dialect translations (the V034 conventions): TIMESTAMPTZ -> TEXT (RFC 3339);
-- cirislens.<table> -> cirislens_<table>.
-- No BEGIN/COMMIT: refinery wraps each migration in its own transaction (V019 rule).

CREATE TABLE cirislens_key_escrows (
    escrow_id  TEXT NOT NULL PRIMARY KEY,
    key_id     TEXT NOT NULL,
    org_id     TEXT NOT NULL,
    escrow_type TEXT NOT NULL,
    custodian  TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    CONSTRAINT key_escrows_type CHECK (escrow_type IN ('steward', 'attorney', 'dual_custody')),
    CONSTRAINT key_escrows_status CHECK (status IN ('active', 'recovered', 'revoked', 'expired'))
);

CREATE INDEX idx_key_escrows_org ON cirislens_key_escrows (org_id);
CREATE INDEX idx_key_escrows_key ON cirislens_key_escrows (key_id);
