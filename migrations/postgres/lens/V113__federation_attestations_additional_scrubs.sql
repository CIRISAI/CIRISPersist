-- V113 — `federation_attestations.additional_scrubs`
-- v24.0.0 (CIRISPersist#557/#556)
--
-- SQLITE PARITY: migrations/sqlite/lens/V113__federation_attestations_additional_scrubs.sql
--
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
-- ENCODING: TEXT holding a JSON array, NOT JSONB — deliberate parity with V096
-- (`federation_keys.additional_scrubs`) and with SQLite, so the two backends
-- round-trip byte-identical `ScrubSig` sets through `serde_json`.
--
-- BYTE-STABILITY: the Rust field is
-- `#[serde(default, skip_serializing_if = "Vec::is_empty")]`, so an ordinary
-- single-scrub row serializes with no `additional_scrubs` key and its
-- `persist_row_hash` is byte-identical to the pre-v24 value. The DEFAULT '[]'
-- therefore leaves every existing row's hash and signature untouched.

ALTER TABLE cirislens.federation_attestations
    ADD COLUMN IF NOT EXISTS additional_scrubs TEXT NOT NULL DEFAULT '[]';

COMMENT ON COLUMN cirislens.federation_attestations.additional_scrubs IS
    'v24.0.0 (CIRISPersist#556) — JSON array of the 2nd..Nth ScrubSig entries '
    'over the SAME canonical attestation_envelope as the base scrub. Empty '
    'array = single-scrub row (wire-absent, persist_row_hash unchanged).';
