-- V100 — CIRISPersist#413 (CC 3.3.6.2 / part_3 §1056, §1331): the transport-
--        binding trust provenance tag. Postgres dialect. SQLite parity:
--        sqlite/lens/V100.
--
-- A transport_destination binding is either ROOTED (a federation-key-signed
-- identity_occurrence / root_binding verified the announced key against
-- federation_keys — authoritative, part_3 §1054) or ADVISORY (a self-consistent
-- announce whose key is unknown/not-yet-rooted — a routing hint only, never an
-- authorization, part_3 §1056). The substrate ADMITS + RECORDS both; the trust
-- that the key owns the destination is composed by the CONSUMER (routing prefers
-- rooted; content gates on trust). Competing claims on one dest-hash (the AV-42
-- spoof) are admitted as distinct rows (the composite PK already keys on
-- occurrence_key_id) and resolved by routing-time PREFERENCE, NOT a substrate
-- reject.
--
-- NOT NULL DEFAULT 'rooted': pre-#413 rows were all authoritative-by-assumption
-- (canonical priming), so they backfill to 'rooted'. New writes set it
-- explicitly. Refinery wraps this in its own transaction.

ALTER TABLE cirislens.transport_destinations
    ADD COLUMN IF NOT EXISTS binding_provenance TEXT NOT NULL DEFAULT 'rooted';
