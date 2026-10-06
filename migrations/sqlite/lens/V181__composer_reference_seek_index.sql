-- V181 — structural composers keyed by the row they name, SQLite dialect
-- v53.1.7 (CIRISEdge PR #818: `live_conferrals` → `list_attestations_referencing`
-- was 13 of 16 stack samples, 96% of a 5,310 s round, on a canonical-like seed)
--
-- POSTGRES PARITY: migrations/postgres/lens/V181__composer_reference_seek_index.sql
--
-- `list_attestations_referencing(target)` asks for every `withdraws` /
-- `recants` / `supersedes` naming one row, by ANY attester. V107's
-- `federation_attestations_composer_ref` carries the same extraction but
-- LEADS with `attesting_key_id`, which this read never pins, so every call
-- scanned the whole table. This index leads with the reference: the read
-- becomes `SEARCH … (references=? AND attestation_type=?)`, one probe per
-- composer type. The expression is spelled exactly as the read spells it.
--
-- `IF NOT EXISTS`; no backfill: an index is derived.

CREATE INDEX IF NOT EXISTS federation_attestations_reference_seek
    ON federation_attestations (
        json_extract(attestation_envelope, '$.references_attestation_id'),
        attestation_type
    );
