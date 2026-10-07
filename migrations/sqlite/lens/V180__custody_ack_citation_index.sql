-- V180 — a device's custody reports, keyed by the blob they cite, SQLite dialect
-- v53.1.6 (CIRISEdge's heap harness: `list_attestations_by(device)` at ~7 KB
-- of heap per row — 59 MB for an 8,252-row author — per custody question)
--
-- POSTGRES PARITY: migrations/postgres/lens/V180__custody_ack_citation_index.sql
--
-- `custody_acks_of(device, blob)` read every row the device ever authored
-- to find its `custody:ack:v1` reports about one blob. The dimension is
-- V137-seekable; the blob is the single element of the envelope's
-- `evidence_refs` (`custody_ack_envelope` writes exactly one, and
-- `parse_custody_ack` refuses any other count), which no index carried.
-- This one does: `(attester, dimension, evidence_refs[0])` is the exact
-- key of `list_attestations_by_dimension_citing`. Postgres already holds a
-- GIN over `evidence_refs` (V106) for containment; this is the ordered
-- equality seek both dialects can share.
--
-- `IF NOT EXISTS`; no backfill: an index is derived.

CREATE INDEX IF NOT EXISTS federation_attestations_attester_dimension_citation
    ON federation_attestations (
        attesting_key_id,
        dimension,
        json_extract(attestation_envelope, '$.evidence_refs[0]')
    );
