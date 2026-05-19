-- V037 — service-token revocation substrate, SQLite dialect
-- (v1.5.23, CIRISPersist#64).
--
-- Postgres parity. TIMESTAMPTZ → TEXT (RFC 3339).

CREATE TABLE cirislens_revoked_service_tokens (
    token_hash  TEXT PRIMARY KEY,
    revoked_at  TEXT NOT NULL,
    revoked_by  TEXT NOT NULL,
    reason      TEXT NOT NULL
);
