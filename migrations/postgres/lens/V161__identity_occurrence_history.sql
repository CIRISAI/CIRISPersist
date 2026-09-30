-- V161 — every admitted occurrence assertion, kept
-- v52.0.0 (CIRISPersist#930, FSD SECOND_DEVICE.md §8.5)
--
-- SQLITE PARITY: migrations/sqlite/lens/V161__identity_occurrence_history.sql
-- (the rationale lives there).
--
-- Append-only history of every assertion either put door admits, read by
-- the node-bearing fold so a renewal or a re-signing never changes a verdict
-- at an earlier instant. `attesting_key_id` is '' for a trusted-local row.
-- The backfill copies the current rows (pre-V161 history never existed).
CREATE TABLE IF NOT EXISTS cirislens.federation_identity_occurrence_history (
    identity_key_id     TEXT NOT NULL,
    occurrence_key_id   TEXT NOT NULL,
    asserted_at         TIMESTAMPTZ NOT NULL,
    valid_until         TIMESTAMPTZ,
    attesting_key_id    TEXT NOT NULL DEFAULT '',
    signed_envelope     TEXT,
    signature           TEXT,
    PRIMARY KEY (identity_key_id, occurrence_key_id, asserted_at, attesting_key_id)
);

CREATE INDEX IF NOT EXISTS federation_identity_occurrence_history_by_occurrence
    ON cirislens.federation_identity_occurrence_history (occurrence_key_id);

INSERT INTO cirislens.federation_identity_occurrence_history (
    identity_key_id, occurrence_key_id, asserted_at, valid_until,
    attesting_key_id, signed_envelope, signature
)
SELECT identity_key_id, occurrence_key_id, asserted_at, valid_until,
       COALESCE(attesting_key_id, ''), signed_envelope, signature
  FROM cirislens.federation_identity_occurrences
ON CONFLICT DO NOTHING;
