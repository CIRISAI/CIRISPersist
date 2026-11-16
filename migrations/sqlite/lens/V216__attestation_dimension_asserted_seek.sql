-- V216 — the exact-dimension attestation read, in its page order. SQLite
-- dialect. v62.0.0 (WASM_NODE FSD §6.4; the readiness audit's P10).
--
-- POSTGRES PARITY: migrations/postgres/lens/V216__attestation_dimension_asserted_seek.sql
--
-- `list_attestations` with one attester (or one subject) and an exact
-- dimension had two candidate indexes, V137's `(attesting_key_id,
-- dimension)` / V180's `(…, dimension, evidence_refs[0])` and V004's
-- `(attesting_key_id, asserted_at DESC)`, and neither yields the page
-- order `asserted_at DESC, attestation_id DESC` under both equalities. So
-- the read either walked the attester's whole history in time order,
-- filtering the dimension per row, or (with statistics, as measured on
-- the browser node at 100k rows) sought the dimension and then sorted
-- every match: about 60k rows of 11 KB in a TEMP B-TREE, 513 ms, to keep
-- 1000. Same defect class as CIRISServer#575.
--
-- These two put the page order after both equalities: the seek walks the
-- (key, dimension) slice newest-first, in the cursor's exact order
-- (`attestation_id` breaks `asserted_at` ties), and stops at the LIMIT.
-- No sort. The read pins them with INDEXED BY (the V212 precedent).
--
-- `IF NOT EXISTS`; no backfill: an index is derived.

CREATE INDEX IF NOT EXISTS federation_attestations_attester_dimension_asserted
    ON federation_attestations (
        attesting_key_id,
        dimension,
        asserted_at DESC,
        attestation_id DESC
    );

CREATE INDEX IF NOT EXISTS federation_attestations_attested_dimension_asserted
    ON federation_attestations (
        attested_key_id,
        dimension,
        asserted_at DESC,
        attestation_id DESC
    );
