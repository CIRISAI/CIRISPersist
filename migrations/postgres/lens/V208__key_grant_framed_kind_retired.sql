-- V208 — the KeyGrant framed kind retires. Postgres dialect. v61
-- (CIRISPersist#991; CC 3.3.2).
--
-- SQLITE PARITY: migrations/sqlite/lens/V208__key_grant_framed_kind_retired.sql
--
-- WHY
-- ---
-- Since v55.0.0 (CIRISPersist#989) a key grant is one `scores` row per
-- recipient on `key_grant:{content,epoch,stream}:v1`. Those rows are served,
-- advertised and fetched as `Attestation` entries. The `KeyGrant` kind named
-- the plane the rows project into. It has now joined `RETIRED_FRAMED`, so a
-- peer's advertisement of a `KeyGrant` hash is refused.
--
-- HOW
-- ---
-- Any wire-index row (V111 `signed_wire_index`) or peer advertisement (V134
-- `known_wire_hashes`) still naming the kind is deleted. Nothing is lost: the
-- rows ride the attestation kind's own entries. Forward-only, like every
-- migration here.

DELETE FROM cirislens.signed_wire_index WHERE kind = 'KeyGrant';

DELETE FROM cirislens.known_wire_hashes WHERE kind = 'KeyGrant';
