-- V154 — a family's roster converges both ways
-- v49.0.0 (CIRISPersist#910, FSD ROOM_ROSTER_AUTHORITY.md §10 items 1–2)
--
-- POSTGRES PARITY: migrations/postgres/lens/V154__family_roster_plane.sql
--
-- # Why
--
-- V151 gave ROOMS an addition plane and a three-part revocation key; families
-- kept growing by rewriting the family RECORD (`add_family_member` UPDATEd
-- `members`), and a rewritten record reaches no peer: the replicated
-- `put_family` is INSERT-only, so a peer keeps its first copy. A removed
-- family member could not be re-added either — the revocation key was
-- `(family_key_id, removed_identity_key_id)`, so a second removal after a
-- re-add had nowhere to go.
--
-- # What changes
--
-- 1. `federation_family_membership_revocations` — PRIMARY KEY gains
--    `effective_at` (a re-added member can be removed again; an exact retry is
--    still the #861 no-op). Every column (V153's `cosignatures` included) and
--    every index is kept; the group FK stays on `federation_families` (V151).
-- 2. `federation_family_membership_widenings` — the addition plane, the
--    structural mirror of `federation_community_membership_widenings`
--    (V151 + V153's `cosignatures`).
--
-- # The rebuild
--
-- sqlite cannot alter a PRIMARY KEY in place. The table has no referrer and no
-- self-FK, so the `_new` + RENAME shape is safe (V151 rebuilt this same table
-- the same way). Explicit column lists; every index re-created under its name.

-- ─── 1. family revocations: PK + effective_at ──────────────────────────
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
    cosignatures             TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (family_key_id, removed_identity_key_id, effective_at)
);
INSERT INTO federation_family_membership_revocations_new (
    family_key_id, removed_identity_key_id, removed_at, effective_at, reason,
    witness_set, persist_row_hash, authority_key_id, scrub_signature_classical,
    scrub_signature_pqc, admitted_at, cosignatures)
SELECT family_key_id, removed_identity_key_id, removed_at, effective_at, reason,
       witness_set, persist_row_hash, authority_key_id, scrub_signature_classical,
       scrub_signature_pqc, admitted_at, cosignatures
  FROM federation_family_membership_revocations;
DROP TABLE federation_family_membership_revocations;
ALTER TABLE federation_family_membership_revocations_new
    RENAME TO federation_family_membership_revocations;
CREATE INDEX federation_family_membership_revocations_effective
    ON federation_family_membership_revocations (effective_at);
CREATE INDEX federation_family_membership_revocations_by_member
    ON federation_family_membership_revocations (removed_identity_key_id);
CREATE INDEX federation_family_membership_revocations_admitted
    ON federation_family_membership_revocations
       (COALESCE(admitted_at, removed_at), family_key_id, removed_identity_key_id, effective_at);

-- ─── 2. the family widening plane ─────────────────────────────────────
CREATE TABLE federation_family_membership_widenings (
    family_key_id             TEXT NOT NULL REFERENCES federation_families(family_key_id),
    member_key_id             TEXT NOT NULL REFERENCES federation_keys(key_id),
    joined_at                 TEXT NOT NULL,
    effective_at              TEXT NOT NULL,
    role                      TEXT,
    persist_row_hash          TEXT NOT NULL,
    authority_key_id          TEXT,
    scrub_signature_classical TEXT,
    scrub_signature_pqc       TEXT,
    admitted_at               TEXT NOT NULL,
    cosignatures              TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (family_key_id, member_key_id, effective_at)
);
CREATE INDEX federation_family_membership_widenings_effective
    ON federation_family_membership_widenings (effective_at);
CREATE INDEX federation_family_membership_widenings_by_member
    ON federation_family_membership_widenings (member_key_id);
CREATE INDEX federation_family_membership_widenings_admitted
    ON federation_family_membership_widenings
       (COALESCE(admitted_at, joined_at), family_key_id, member_key_id, effective_at);
