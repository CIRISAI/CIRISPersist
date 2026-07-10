-- V101 — CIRISPersist#416: drop the transport_destinations → federation_keys FK.
--        SQLite dialect. Postgres parity: postgres/lens/V101.
--
-- V078 declared occurrence_key_id NOT NULL REFERENCES federation_keys(key_id)
-- "to keep an address from naming an unknown occurrence key." But #413 (V100)
-- made this table record ADVISORY bindings (CC 3.3.6.2, part_3 §1056/§1331): a
-- self-consistent announce whose signing key is NOT-yet-rooted and therefore
-- NOT in federation_keys. The FK rejects exactly the row admit-advisory must
-- record (field-observed: put_transport_destination -> FOREIGN KEY constraint
-- failed, provenance=Advisory). The FK's guarantee is precisely what
-- admit-advisory supersedes; the replacement correctness is the binding_provenance
-- tag + routing-time preference (prefer Rooted over Advisory; content gates on
-- trust, CC 6 N1). Rooted keys are in federation_keys anyway, so dropping the FK
-- does not weaken them.
--
-- SQLite can't ALTER TABLE ... DROP CONSTRAINT, so recreate the table without the
-- REFERENCES, preserving the composite PK, the by-occurrence index, and every
-- V098/V099/V100 column. Refinery wraps this in its own transaction.

CREATE TABLE transport_destinations_new (
    occurrence_key_id               TEXT NOT NULL,
    transport_kind                  TEXT NOT NULL,
    destination                     TEXT NOT NULL,
    asserted_at                     TEXT NOT NULL,   -- RFC-3339 UTC
    last_seen_at                    TEXT,            -- RFC-3339 UTC, advisory
    transport_ed25519_pubkey_base64 TEXT,            -- V098 (#397)
    transport_x25519_pubkey_base64  TEXT,            -- V099 (#411)
    binding_provenance              TEXT NOT NULL DEFAULT 'rooted',  -- V100 (#413)
    PRIMARY KEY (occurrence_key_id, transport_kind, destination)
);

INSERT INTO transport_destinations_new
    (occurrence_key_id, transport_kind, destination, asserted_at, last_seen_at,
     transport_ed25519_pubkey_base64, transport_x25519_pubkey_base64, binding_provenance)
SELECT
     occurrence_key_id, transport_kind, destination, asserted_at, last_seen_at,
     transport_ed25519_pubkey_base64, transport_x25519_pubkey_base64, binding_provenance
FROM transport_destinations;

DROP TABLE transport_destinations;
ALTER TABLE transport_destinations_new RENAME TO transport_destinations;

CREATE INDEX transport_destinations_by_occurrence
    ON transport_destinations (occurrence_key_id);
