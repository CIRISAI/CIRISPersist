-- V216 — the exact-dimension attestation read, in its page order. Postgres
-- dialect. v62.0.0 (WASM_NODE FSD §6.4; the readiness audit's P10).
--
-- SQLITE PARITY: migrations/sqlite/lens/V216__attestation_dimension_asserted_seek.sql
-- See that file's header for the rationale. Here the read sought V137's
-- `(attesting_key_id, dimension COLLATE "C")` and sorted every match
-- before its LIMIT. With the page order after both equalities the scan
-- returns rows in `asserted_at DESC, attestation_id DESC` order and the
-- LIMIT stops it. The dimension is `COLLATE "C"` for V137's reason: the
-- predicate and the index must name the same expression.
--
-- Plain CREATE INDEX inside the migration transaction (V042's precedent),
-- not CONCURRENTLY.

CREATE INDEX IF NOT EXISTS federation_attestations_attester_dimension_asserted
    ON cirislens.federation_attestations (
        attesting_key_id,
        (dimension COLLATE "C"),
        asserted_at DESC,
        attestation_id DESC
    );

CREATE INDEX IF NOT EXISTS federation_attestations_attested_dimension_asserted
    ON cirislens.federation_attestations (
        attested_key_id,
        (dimension COLLATE "C"),
        asserted_at DESC,
        attestation_id DESC
    );
