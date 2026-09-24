-- V151 — a room's roster converges both ways
-- v48.0.0 (CIRISPersist#860, FSD/ROOM_ROSTER_PLANES.md §3.1–§3.3)
--
-- POSTGRES PARITY: migrations/postgres/lens/V151__room_roster_planes.sql
--
-- # Why
--
-- A family and a community are KEYLESS identifiers (the constitution's
-- family has no key; a room is not a person). Both membership-revocation
-- tables nevertheless declared `<group>_key_id REFERENCES federation_keys`
-- (V067), so a room admitted the way `put_community` allows — with no key
-- row of its own — could never be revoked from: the FK failed at the first
-- removal, and the §15 DEK rotation behind it was unreachable. persist's
-- own fixtures registered the group id as a `user` key first, which is why
-- it never surfaced (CIRISEdge#608 / #613 surfaced it on the first pair
-- room that widened).
--
-- Growth had the mirror-image problem: `add_community_member` mutated the
-- community RECORD in place, and a record with the same id and a new hash
-- is a fork at every peer. Removal converges because it is an append plane;
-- growth becomes one here: `federation_community_membership_widenings`.
--
-- # What changes
--
-- 1. `federation_family_membership_revocations.family_key_id` →
--    REFERENCES federation_families(family_key_id).
-- 2. `federation_community_membership_revocations.community_key_id` →
--    REFERENCES federation_communities(community_key_id), and its PRIMARY
--    KEY gains `effective_at`: a member can be re-added, so a member can be
--    removed again; an exact retry is still the #861 no-op.
-- 3. `federation_community_membership_widenings` — the addition plane, the
--    structural mirror of the revocation table (PK includes `effective_at`
--    for the same reason).
--
-- # The rebuild
--
-- sqlite cannot alter a FOREIGN KEY or a PRIMARY KEY in place. Neither table
-- has a referrer and neither has a self-FK, so the `_new` + RENAME shape is
-- safe here (V141's header measured why it is NOT safe on `federation_keys`;
-- the six referrer-less tables would survive it, and these two are of that
-- kind). Explicit column lists; every index re-created under its V141 name.
--
-- Rows that named a group with NO row in its group table are dropped by the
-- copy: they were unreachable by every fold (`active_*_members` looks the
-- group up first and refuses an unknown one), could only have been written
-- before this version by a caller naming a group that never existed, and
-- would violate the new FK at the copy. Their count is not silently zero —
-- the Rust migration witness `v151_rebuild_...` compares row counts before
-- and after and REPORTS any difference.

-- ─── 1. family revocations: FK → federation_families ───────────────────
CREATE TABLE federation_family_membership_revocations_new (
    family_key_id            TEXT NOT NULL REFERENCES federation_families(family_key_id),
    removed_identity_key_id  TEXT NOT NULL REFERENCES federation_keys(key_id),
    removed_at               TEXT NOT NULL,
    effective_at             TEXT NOT NULL,
    reason                   TEXT,
    witness_set              TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(witness_set) AND json_type(witness_set) = 'array'),
    persist_row_hash         TEXT NOT NULL,
    authority_key_id         TEXT,
    scrub_signature_classical TEXT,
    scrub_signature_pqc      TEXT,
    admitted_at              TEXT NOT NULL,
    PRIMARY KEY (family_key_id, removed_identity_key_id)
);
INSERT INTO federation_family_membership_revocations_new (
    family_key_id, removed_identity_key_id, removed_at, effective_at, reason,
    witness_set, persist_row_hash, authority_key_id, scrub_signature_classical,
    scrub_signature_pqc, admitted_at)
SELECT family_key_id, removed_identity_key_id, removed_at, effective_at, reason,
       witness_set, persist_row_hash, authority_key_id, scrub_signature_classical,
       scrub_signature_pqc, admitted_at
  FROM federation_family_membership_revocations
 WHERE family_key_id IN (SELECT family_key_id FROM federation_families);
DROP TABLE federation_family_membership_revocations;
ALTER TABLE federation_family_membership_revocations_new
    RENAME TO federation_family_membership_revocations;
CREATE INDEX federation_family_membership_revocations_effective
    ON federation_family_membership_revocations (effective_at);
CREATE INDEX federation_family_membership_revocations_by_member
    ON federation_family_membership_revocations (removed_identity_key_id);
CREATE INDEX federation_family_membership_revocations_admitted
    ON federation_family_membership_revocations
       (COALESCE(admitted_at, removed_at), family_key_id, removed_identity_key_id);

-- ─── 2. community revocations: FK → federation_communities, PK + effective_at ─
CREATE TABLE federation_community_membership_revocations_new (
    community_key_id         TEXT NOT NULL REFERENCES federation_communities(community_key_id),
    removed_identity_key_id  TEXT NOT NULL REFERENCES federation_keys(key_id),
    removed_at               TEXT NOT NULL,
    effective_at             TEXT NOT NULL,
    reason                   TEXT,
    witness_set              TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(witness_set) AND json_type(witness_set) = 'array'),
    persist_row_hash         TEXT NOT NULL,
    authority_key_id         TEXT,
    scrub_signature_classical TEXT,
    scrub_signature_pqc      TEXT,
    admitted_at              TEXT NOT NULL,
    PRIMARY KEY (community_key_id, removed_identity_key_id, effective_at)
);
INSERT INTO federation_community_membership_revocations_new (
    community_key_id, removed_identity_key_id, removed_at, effective_at, reason,
    witness_set, persist_row_hash, authority_key_id, scrub_signature_classical,
    scrub_signature_pqc, admitted_at)
SELECT community_key_id, removed_identity_key_id, removed_at, effective_at, reason,
       witness_set, persist_row_hash, authority_key_id, scrub_signature_classical,
       scrub_signature_pqc, admitted_at
  FROM federation_community_membership_revocations
 WHERE community_key_id IN (SELECT community_key_id FROM federation_communities);
DROP TABLE federation_community_membership_revocations;
ALTER TABLE federation_community_membership_revocations_new
    RENAME TO federation_community_membership_revocations;
CREATE INDEX federation_community_membership_revocations_effective
    ON federation_community_membership_revocations (effective_at);
CREATE INDEX federation_community_membership_revocations_by_member
    ON federation_community_membership_revocations (removed_identity_key_id);
CREATE INDEX federation_community_membership_revocations_admitted
    ON federation_community_membership_revocations
       (COALESCE(admitted_at, removed_at), community_key_id, removed_identity_key_id, effective_at);

-- ─── 3. the widening plane ─────────────────────────────────────────────
CREATE TABLE federation_community_membership_widenings (
    community_key_id          TEXT NOT NULL REFERENCES federation_communities(community_key_id),
    member_key_id             TEXT NOT NULL REFERENCES federation_keys(key_id),
    joined_at                 TEXT NOT NULL,
    effective_at              TEXT NOT NULL,
    role                      TEXT,
    persist_row_hash          TEXT NOT NULL,
    authority_key_id          TEXT,
    scrub_signature_classical TEXT,
    scrub_signature_pqc       TEXT,
    admitted_at               TEXT NOT NULL,
    PRIMARY KEY (community_key_id, member_key_id, effective_at)
);
CREATE INDEX federation_community_membership_widenings_effective
    ON federation_community_membership_widenings (effective_at);
CREATE INDEX federation_community_membership_widenings_by_member
    ON federation_community_membership_widenings (member_key_id);
CREATE INDEX federation_community_membership_widenings_admitted
    ON federation_community_membership_widenings
       (COALESCE(admitted_at, joined_at), community_key_id, member_key_id, effective_at);
