-- V098 — CIRISPersist#397: add the transport-tier Ed25519 pubkey to a
--        transport_destination row. SQLite dialect. Postgres parity:
--        postgres/lens/V098.
--
-- An explicit-hash canonical peer (a v7.0.0 baked-IP destination like
-- `ciris-canonical-1`) CANNOT announce by design (Leviculum
-- ExplicitHashCannotAnnounce), so the only rooting path is edge's
-- out-of-band prime_peer(key_id, dest_hash, transport_ed25519_pubkey_b64)
-- (CIRISEdge#214). The `destination` column already carries the Reticulum
-- dest hash, but the transport-tier Ed25519 is a DISTINCT, edge-owned key
-- (the keyring-backed RNS transport identity, CIRISEdge#99) that is NOT
-- derivable from the identity-tier Ed25519 — so a peer cannot compute it
-- from the KeyRecord. The node derives it at edge-runtime
-- (transport_identity_pubkeys()) and publishes it HERE, so a peer that reads
-- the companion transport_destination row has the full (dest_hash,
-- transport_ed25519) pair prime_peer needs.
--
-- Nullable + additive: pre-#397 rows (and non-Reticulum kinds — websocket /
-- https carry no RNS transport key) leave it NULL. base64 (standard
-- alphabet) of the 32 raw Ed25519 bytes. Refinery wraps this in its own
-- transaction.

ALTER TABLE transport_destinations
    ADD COLUMN transport_ed25519_pubkey_base64 TEXT;
