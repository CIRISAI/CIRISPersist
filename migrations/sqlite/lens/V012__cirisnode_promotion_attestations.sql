-- V012 — CIRISNodeCore canonical-promotion attestations, SQLite dialect
-- (v0.9.4, CIRISPersist#40).
--
-- Postgres parity (postgres/lens/V012, v0.7.2 / #32): same shape, same
-- audit envelope, same target_kind CHECK enum.
--
-- Dialect translations:
--
--   PostgreSQL                       → SQLite
--   ─────────────────────────────────────────────────────────────────
--   UUID attestation_id              → TEXT (36-char hyphenated)
--   UUID[] target_ids                → TEXT (JSON array of UUID strings)
--   BYTEA original_content_hash      → BLOB
--   JSONB aggregate_evidence         → TEXT (canonical JSON)
--   TIMESTAMPTZ                      → TEXT (RFC 3339)
--   GIN index on target_ids          → not directly available; reverse-
--                                       lookup uses json_each() table-
--                                       valued function at query time.
--                                       (Index on attested_at /
--                                       target_kind keeps the forward
--                                       lookups fast.)

CREATE TABLE IF NOT EXISTS cirisnode_promotion_attestations (
    attestation_id                TEXT PRIMARY KEY,
    target_kind                   TEXT NOT NULL
        CHECK (target_kind IN (
            'contribution',
            'vote',
            'moderation_event',
            'slashing_attestation',
            'reconsideration_attestation'
        )),
    target_ids                    TEXT NOT NULL,
    attested_by                   TEXT NOT NULL,
    aggregate_evidence            TEXT NOT NULL,
    attested_at                   TEXT NOT NULL,
    signature                     TEXT NOT NULL,
    signing_key_id                TEXT NOT NULL,
    signature_verified            INTEGER NOT NULL DEFAULT 0,
    original_content_hash         BLOB,
    scrub_signature_classical     TEXT,
    scrub_signature_pqc           TEXT,
    scrub_key_id                  TEXT,
    scrub_timestamp               TEXT,
    pqc_completed_at              TEXT,
    persist_row_hash              TEXT NOT NULL,
    created_at                    TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);

CREATE INDEX IF NOT EXISTS promotion_attestations_target_kind
    ON cirisnode_promotion_attestations (target_kind);
CREATE INDEX IF NOT EXISTS promotion_attestations_attested_by
    ON cirisnode_promotion_attestations (attested_by);
CREATE INDEX IF NOT EXISTS promotion_attestations_attested_at
    ON cirisnode_promotion_attestations (attested_at);
