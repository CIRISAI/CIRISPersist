-- V190 — the holder directory, keyed by the blob a holding claim cites, SQLite dialect
-- v55.0.0 (CIRISPersist#989, CC 3.1.3.3 / 5.3.2.1, CIRISConstitution#141)
--
-- POSTGRES PARITY: migrations/postgres/lens/V190__holding_claim_citation_index.sql
--
-- `custody:ack:v1` is the one holding claim at every tier, and at
-- `federation` its `here` rows are the holder directory. "Who holds this
-- blob" asks the claims of EVERY attester that cite one digest; V180 keys a
-- device's own claims `(attester, dimension, evidence_refs[0])`, which a
-- seek without the attester cannot use. This is the attester-free twin:
-- `(dimension, evidence_refs[0])` is the exact key of
-- `list_attestations_citing_by_dimension`. It replaces the retired
-- `holds_bytes:sha256:{prefix}` type-column seek.
--
-- `IF NOT EXISTS`; no backfill: an index is derived.

CREATE INDEX IF NOT EXISTS federation_attestations_dimension_citation
    ON federation_attestations (
        dimension,
        json_extract(attestation_envelope, '$.evidence_refs[0]')
    );
