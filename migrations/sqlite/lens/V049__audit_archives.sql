-- V049 — audit_archives table, SQLite dialect (v2.7.0, CIRISPersist#107).
--
-- Postgres parity (postgres/lens/V049): same column shapes, same
-- AV-51 tenant isolation. Dialect translations:
--
--   PostgreSQL                      → SQLite
--   ─────────────────────────────────────────────────────────────────
--   UUID                            → TEXT (36-char hyphenated)
--   TIMESTAMPTZ                     → TEXT (RFC 3339)
--   BYTEA chain_anchor / archive_bytes → BLOB
--   now()                           → strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
--
-- See postgres/lens/V049 for the architectural rationale + chain-
-- anchor semantics.

CREATE TABLE IF NOT EXISTS cirislens_audit_archives (
    archive_id     TEXT    PRIMARY KEY,
    tenant_id      TEXT    NOT NULL,
    from_ts        TEXT    NOT NULL,
    to_ts          TEXT    NOT NULL,
    rows_archived  INTEGER NOT NULL CHECK (rows_archived >= 0),
    chain_anchor   BLOB    NOT NULL CHECK (length(chain_anchor) = 32),
    archive_bytes  BLOB    NOT NULL,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (from_ts < to_ts)
);

CREATE INDEX IF NOT EXISTS audit_archives_tenant_range
    ON cirislens_audit_archives (tenant_id, from_ts, to_ts);
