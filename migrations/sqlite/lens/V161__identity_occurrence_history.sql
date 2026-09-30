-- V161 — every admitted occurrence assertion, kept
-- v52.0.0 (CIRISPersist#930, FSD SECOND_DEVICE.md §8.5)
--
-- POSTGRES PARITY: migrations/postgres/lens/V161__identity_occurrence_history.sql
--
-- # Why
--
-- `federation_identity_occurrences` keeps ONE row per (identity, occurrence):
-- the latest assertion. A renewal moved the binding's start forward, and an
-- identity re-signing the pair overwrote the row the occurrence itself had
-- signed. So the node-bearing fold (CC 3.2 "infrastructure does not vote")
-- could change a verdict at an EARLIER instant after the fact: a roster
-- change judged admissible at t could be judged otherwise later.
--
-- This table is append-only: every assertion either put door admits lands
-- here, including one older than the stored row (the current-state upsert
-- declines it; it is still a verified assertion). The fold reads it; every
-- other reader keeps reading the current-state table.
--
-- `attesting_key_id` is '' for a trusted-local row (no signature), so the
-- key has one spelling in both dialects.
--
-- The backfill copies the current rows: pre-V161 history never existed, so
-- verdicts over pre-V161 instants are the latest-assertion ones.
CREATE TABLE IF NOT EXISTS federation_identity_occurrence_history (
    identity_key_id     TEXT NOT NULL,
    occurrence_key_id   TEXT NOT NULL,
    asserted_at         TEXT NOT NULL,
    valid_until         TEXT,
    attesting_key_id    TEXT NOT NULL DEFAULT '',
    signed_envelope     TEXT,
    signature           TEXT,
    PRIMARY KEY (identity_key_id, occurrence_key_id, asserted_at, attesting_key_id)
);

CREATE INDEX IF NOT EXISTS federation_identity_occurrence_history_by_occurrence
    ON federation_identity_occurrence_history (occurrence_key_id);

INSERT OR IGNORE INTO federation_identity_occurrence_history (
    identity_key_id, occurrence_key_id, asserted_at, valid_until,
    attesting_key_id, signed_envelope, signature
)
SELECT identity_key_id, occurrence_key_id, asserted_at, valid_until,
       COALESCE(attesting_key_id, ''), signed_envelope, signature
  FROM federation_identity_occurrences;
