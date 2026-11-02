-- V212 — the attestation listing's keyset order, SQLite dialect. v61
-- (the canonical's read storm, measured on a copy of the live store).
--
-- POSTGRES PARITY: migrations/postgres/lens/V212__attestation_asserted_seek_index.sql
--
-- `list_attestations` with no attester / subject pin (Server's equivocation
-- detector, the Live default view, a keyset cursor) asks for
-- `ORDER BY asserted_at DESC, attestation_id DESC LIMIT n` under
-- `(asserted_at, attestation_id) < (?, ?)`. Every index carrying
-- `asserted_at` led with a key column (V004's attester / subject pairs,
-- V060's by-target), so no index served that order: each page was a
-- `SCAN federation_attestations` (every envelope) plus a `TEMP B-TREE` sort
-- of every qualifying row before the LIMIT. This index is that order: the
-- cursor's row-value bound seeks it and the walk stops at the LIMIT. The
-- tier predicate is not always present (`tier: None` adds none), so the
-- index does not lead with it. The read pins it with INDEXED BY.
--
-- `IF NOT EXISTS`; no backfill: an index is derived.

CREATE INDEX IF NOT EXISTS federation_attestations_asserted_seek
    ON federation_attestations (asserted_at DESC, attestation_id DESC);

-- And the composers' reference, over composer rows only. V181's
-- `reference_seek` indexes every row, and on almost every row the reference
-- is NULL. Once statistics exist, a store with few or no composers tells the
-- planner that one reference value covers the whole table, and the lifecycle
-- subquery becomes `SCAN c USING INDEX reference_seek` (a full index walk)
-- for every outer row. Its statistics are the composers' own. `expr = ?`
-- implies `expr IS NOT NULL`, so every equality read can use it. The Live
-- lifecycle subquery and the unpinned composer fold name it with INDEXED BY.
CREATE INDEX IF NOT EXISTS federation_attestations_reference_live
    ON federation_attestations (
        json_extract(attestation_envelope, '$.references_attestation_id'),
        attestation_type
    )
    WHERE json_extract(attestation_envelope, '$.references_attestation_id') IS NOT NULL;
