-- V037 — service-token revocation substrate (v1.5.23, CIRISPersist#64).
--
-- Absorbs CIRISAgent's standalone revoked_service_tokens.db file
-- (the last aiosqlite consumer). Final dependency removal blocker
-- for CIRISAgent 2.9.0 Phase 2b.
--
-- token_hash is the PK — a SHA-based digest of the service token
-- the agent's auth_service hashes at revocation time. NOT a wa_id;
-- service tokens don't map to WA certs (see issue #64 for the
-- two-table distinction).
--
-- All four columns NOT NULL: revocations always carry context
-- (when, by whom, why) for the audit trail.

CREATE TABLE cirislens.revoked_service_tokens (
    token_hash  TEXT PRIMARY KEY,
    revoked_at  TIMESTAMPTZ NOT NULL,
    revoked_by  TEXT NOT NULL,
    reason      TEXT NOT NULL
);

COMMENT ON TABLE cirislens.revoked_service_tokens IS
    'v1.5.23 (CIRISPersist#64) — service-token revocation substrate. Absorbs agent revoked_service_tokens.db.';
