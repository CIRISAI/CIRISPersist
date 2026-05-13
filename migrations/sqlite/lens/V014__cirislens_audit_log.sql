-- V014 — hash-chained audit log, SQLite dialect (v0.8.5, CIRISPersist#38).
--
-- Postgres parity (postgres/lens/V014): same column shapes, same
-- AV-49/AV-50/AV-51 semantics. Dialect translations:
--
--   PostgreSQL                      → SQLite
--   ─────────────────────────────────────────────────────────────────
--   JSONB payload                   → TEXT (canonical JSON)
--   UUID                            → TEXT (36-char hyphenated)
--   TIMESTAMPTZ                     → TEXT (RFC 3339)
--   BYTEA prev_hash / entry_hash    → BLOB (32 bytes raw sha256)
--   NOW()                           → datetime('now', 'subsec')
--   UNIQUE (tenant, seq)            → UNIQUE (tenant, seq) (same)
--
-- Hash-chain semantics: same as Postgres. AV-49 entry_hash strips
-- signature + entry_hash from canonical bytes; signature signs
-- canonical(entry minus signature) — INCLUDING the resolved
-- entry_hash. Chain breaks surfaced by verify_chain (AV-50).

CREATE TABLE IF NOT EXISTS cirislens_audit_log (
    entry_id              TEXT PRIMARY KEY,
    sequence_number       INTEGER NOT NULL CHECK (sequence_number >= 1),
    tenant_id             TEXT NOT NULL,
    actor_id              TEXT NOT NULL,
    action_type           TEXT NOT NULL,
    subject_kind          TEXT NOT NULL,
    subject_id            TEXT NOT NULL,
    payload               TEXT NOT NULL,
    prev_hash             BLOB NOT NULL,
    entry_hash            BLOB NOT NULL,
    recorded_at           TEXT NOT NULL,

    -- Audit envelope.
    signature             TEXT NOT NULL,
    signing_key_id        TEXT NOT NULL,
    signature_verified    INTEGER NOT NULL DEFAULT 0,
    persist_row_hash      TEXT NOT NULL,

    UNIQUE (tenant_id, sequence_number)
);

CREATE INDEX IF NOT EXISTS audit_log_tenant_seq
    ON cirislens_audit_log (tenant_id, sequence_number);
CREATE INDEX IF NOT EXISTS audit_log_subject
    ON cirislens_audit_log (subject_kind, subject_id);
CREATE INDEX IF NOT EXISTS audit_log_actor
    ON cirislens_audit_log (actor_id);
CREATE INDEX IF NOT EXISTS audit_log_recorded_at
    ON cirislens_audit_log (recorded_at);
CREATE INDEX IF NOT EXISTS audit_log_action_type
    ON cirislens_audit_log (action_type);
