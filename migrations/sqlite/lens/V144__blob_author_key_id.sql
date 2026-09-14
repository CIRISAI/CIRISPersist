-- V144 — author is not holder, SQLite dialect
-- CIRISPersist#846 (FSD/BLOB_REPLICATION.md §5, I49)
--
-- POSTGRES PARITY: migrations/postgres/lens/V144__blob_author_key_id.sql
--
-- The blob row carried no author. Provenance lives on the referencing
-- attestation, and the `holds_bytes` row names the HOLDER — which, for
-- anything this node stores, is this node. So the one predicate that
-- classified content as proxy ("no local holds_bytes attester is
-- local-or-family") was true of nothing a node ADOPTS from a peer: every
-- relayed blob classified as protected, never force-evicted first, never
-- refused under pressure.
--
--   author_key_id   the `attesting_key_id` of the attestation the blob is a
--                   projection of. Local doors record the writer's DERIVED
--                   federation key id (I23); the adopt door records the
--                   provenance it was handed. NULL = unknown.
--
-- Backfill: NONE, deliberately. Nothing on disk records who authored a
-- pre-V144 row — the holds_bytes attester is the holder, not the author,
-- and a self/family row was never announced at all — so any value written
-- here would be a guess dressed as a fact. `is_proxy_content` treats NULL
-- as unknown ⇒ PROXY: fail toward evictable, never toward protected.
-- A pre-V144 row this node authored is therefore evictable-first under
-- pressure until it is re-announced; a pre-V144 row it relayed is
-- classified exactly as it should have been all along.

ALTER TABLE federation_blobs
    ADD COLUMN author_key_id TEXT NULL;
