-- V200 — a framed occurrence revocation is marked legacy.
-- SQLite dialect. v59.0.0 (sealed-transport floor, operator ruling
-- 2026-10-19; CC 5.3.3.5 E1 option (i)).
--
-- POSTGRES PARITY: migrations/postgres/lens/V200__legacy_framed_occurrence_revocations.sql
--
-- WHY
-- ---
-- v59 retires the framed key-plane carriage: an occurrence's revocation is a
-- `withdraws` against its `identity:occurrence:v1` row (or, for a user-role
-- self's roster key, a two-path proposal). A framed, signed occurrence
-- revocation already held cannot be re-signed as a `withdraws` — persist
-- holds no one's key — so its projection row stays exactly as it is and is
-- MARKED legacy here: the occurrence fold (`list_identity_occurrences_active`)
-- keeps reading it as revoked, and nothing un-revokes it. A row the
-- `withdraws` hook writes after v59 is unsigned and is not legacy.
--
-- HOW
-- ---
-- A framed row is the one that carries the V103 signature trio.

ALTER TABLE federation_identity_occurrence_revocations
    ADD COLUMN legacy_framed INTEGER NOT NULL DEFAULT 0 CHECK (legacy_framed IN (0, 1));

UPDATE federation_identity_occurrence_revocations
   SET legacy_framed = 1
 WHERE signature IS NOT NULL;
