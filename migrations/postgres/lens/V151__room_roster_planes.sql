-- V151 — a room's roster converges both ways
-- v48.0.0 (CIRISPersist#860, FSD/ROOM_ROSTER_PLANES.md §3.1–§3.3)
--
-- SQLITE PARITY: migrations/sqlite/lens/V151__room_roster_planes.sql
-- (that file's header carries the reasoning; this one carries the DDL).
--
-- 1. family revocations: group FK → federation_families.
-- 2. community revocations: group FK → federation_communities; PK gains
--    effective_at (a re-added member can be removed again; an exact retry is
--    still the #861 no-op).
-- 3. the widening plane: federation_community_membership_widenings.
--
-- Rows naming a group with no row in its group table were unreachable by
-- every fold and would violate the new FK; they are deleted first (the
-- migration witness reports the count).

-- ─── 1. family revocations ─────────────────────────────────────────────
DELETE FROM cirislens.federation_family_membership_revocations
 WHERE family_key_id NOT IN (SELECT family_key_id FROM cirislens.federation_families);
DO $$
DECLARE c RECORD;
BEGIN
    FOR c IN
        SELECT con.conname
          FROM pg_constraint con
          JOIN pg_class      rel ON rel.oid = con.conrelid
          JOIN pg_namespace  nsp ON nsp.oid = rel.relnamespace
         WHERE con.contype = 'f'
           AND nsp.nspname = 'cirislens'
           AND rel.relname = 'federation_family_membership_revocations'
           AND pg_get_constraintdef(con.oid) LIKE 'FOREIGN KEY (family_key_id)%'
    LOOP
        EXECUTE format('ALTER TABLE cirislens.federation_family_membership_revocations DROP CONSTRAINT %I', c.conname);
    END LOOP;
END $$;
ALTER TABLE cirislens.federation_family_membership_revocations
    ADD CONSTRAINT federation_family_membership_revocations_family_fkey
    FOREIGN KEY (family_key_id)
    REFERENCES cirislens.federation_families(family_key_id);

-- ─── 2. community revocations ──────────────────────────────────────────
DELETE FROM cirislens.federation_community_membership_revocations
 WHERE community_key_id NOT IN (SELECT community_key_id FROM cirislens.federation_communities);
DO $$
DECLARE c RECORD;
BEGIN
    FOR c IN
        SELECT con.conname
          FROM pg_constraint con
          JOIN pg_class      rel ON rel.oid = con.conrelid
          JOIN pg_namespace  nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = 'cirislens'
           AND rel.relname = 'federation_community_membership_revocations'
           AND ((con.contype = 'f' AND pg_get_constraintdef(con.oid) LIKE 'FOREIGN KEY (community_key_id)%')
                OR con.contype = 'p')
    LOOP
        EXECUTE format('ALTER TABLE cirislens.federation_community_membership_revocations DROP CONSTRAINT %I', c.conname);
    END LOOP;
END $$;
ALTER TABLE cirislens.federation_community_membership_revocations
    ADD CONSTRAINT federation_community_membership_revocations_community_fkey
    FOREIGN KEY (community_key_id)
    REFERENCES cirislens.federation_communities(community_key_id);
ALTER TABLE cirislens.federation_community_membership_revocations
    ADD PRIMARY KEY (community_key_id, removed_identity_key_id, effective_at);

-- ─── 3. the widening plane ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cirislens.federation_community_membership_widenings (
    community_key_id          TEXT NOT NULL
        REFERENCES cirislens.federation_communities(community_key_id),
    member_key_id             TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),
    joined_at                 TIMESTAMPTZ NOT NULL,
    effective_at              TIMESTAMPTZ NOT NULL,
    role                      TEXT,
    persist_row_hash          TEXT NOT NULL,
    authority_key_id          TEXT,
    scrub_signature_classical TEXT,
    scrub_signature_pqc       TEXT,
    admitted_at               TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_key_id, member_key_id, effective_at)
);
CREATE INDEX IF NOT EXISTS federation_community_membership_widenings_effective
    ON cirislens.federation_community_membership_widenings (effective_at);
CREATE INDEX IF NOT EXISTS federation_community_membership_widenings_by_member
    ON cirislens.federation_community_membership_widenings (member_key_id);
CREATE INDEX IF NOT EXISTS federation_community_membership_widenings_admitted
    ON cirislens.federation_community_membership_widenings
       (admitted_at, community_key_id, member_key_id, effective_at);
