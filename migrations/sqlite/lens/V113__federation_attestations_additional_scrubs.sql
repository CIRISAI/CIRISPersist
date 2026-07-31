-- V113 — `federation_attestations.additional_scrubs`
-- v24.0.0 (CIRISPersist#557/#556)
--
-- POSTGRES PARITY: migrations/postgres/lens/V113__federation_attestations_additional_scrubs.sql
-- (same column name, same TEXT-JSON encoding, same '[]' default). Dialect
-- translation for this file:
--   postgres `ADD COLUMN IF NOT EXISTS`  → sqlite `ADD COLUMN` (refinery runs
--                                          each migration exactly once)
--   postgres `COMMENT ON COLUMN`         → this header
--   postgres (no json CHECK)             → sqlite `json_valid` CHECK, matching
--                                          V055's `subject_key_ids` precedent
--
-- WHAT
-- ----
-- The 2nd..Nth scrub signatures over the SAME canonical `attestation_envelope`
-- — the attestation-plane twin of `federation_keys.additional_scrubs` (V096).
-- Scrub #1 stays in the base `scrub_key_id` / `scrub_signature_*` columns.
--
-- WHY (CIRISPersist#556)
-- ---------------------
-- One genesis ceremony, two planes, two different outcomes: the serve-node KEY
-- RECORD carried `scrub A1 + additional_scrubs [B1]` and proved 2-of-n, while
-- the `genesis-charter` ATTESTATION that makes A1 a trust root carried one
-- `scrub_key_id` and proved 1-of-n. The 2-of-3 that authorized the charter was
-- verified at `verify_bundle` and then unrecoverable: a peer receiving the
-- charter by replication could only ever answer "A1 asserted it". This column
-- is what lets a replicated row prove its own m-of-n.
--
-- BYTE-STABILITY
-- --------------
-- The Rust field is `#[serde(default, skip_serializing_if = "Vec::is_empty")]`,
-- so an ordinary single-scrub row serializes with no `additional_scrubs` key at
-- all and its `persist_row_hash` is byte-identical to the pre-v24 value. The
-- DEFAULT '[]' therefore leaves every existing row's hash and signature
-- untouched. A NON-empty set IS covered by `persist_row_hash` (and by the
-- ingest verifier — see `verify_row_hybrid_signature`), which is the whole
-- point: the preserve set must equal the verified set (#541).

ALTER TABLE federation_attestations
    ADD COLUMN additional_scrubs TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(additional_scrubs)
               AND json_type(additional_scrubs) = 'array');
