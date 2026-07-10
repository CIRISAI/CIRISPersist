-- V099 — CIRISPersist#411: add the transport-tier X25519 (KEX) pubkey to a
--        transport_destination row. Postgres dialect. SQLite parity:
--        sqlite/lens/V099.
--
-- Replication seals envelopes to a peer with its transport-tier X25519 — the
-- FIRST 32 bytes of the 64-byte Reticulum transport identity
-- (x25519(32) ‖ ed25519(32)). V098 added the ed25519 half (verification /
-- prime_peer); this adds the x25519 KEX half so the COMPLETE transport identity
-- persists. Without it, after a restart resolve_peer_kex_pubkeys returns None
-- and replication cannot seal (CIRISServer#216: 0 envelopes). Persist is the
-- source of truth for rooted-peer transport state — the node/edge reloads every
-- binding on boot (list_all_transport_destinations), never re-announces.
--
-- Nullable + additive: pre-#411 rows (and non-Reticulum kinds) leave it NULL.
-- base64 (standard alphabet) of the 32 raw X25519 bytes. This is the
-- TRANSPORT-tier link key, distinct from the identity-tier content-encryption
-- X25519 (§5.6.8.8.2). Refinery wraps this in its own transaction.

ALTER TABLE cirislens.transport_destinations
    ADD COLUMN IF NOT EXISTS transport_x25519_pubkey_base64 TEXT;
