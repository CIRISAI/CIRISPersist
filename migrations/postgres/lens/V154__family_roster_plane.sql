-- V154 — a family's roster converges both ways
-- v49.0.0 (CIRISPersist#910, FSD ROOM_ROSTER_AUTHORITY.md §10 items 1–2)
--
-- SQLITE PARITY: migrations/sqlite/lens/V154__family_roster_plane.sql
-- (that file's header carries the reasoning; this one carries the DDL).
--
-- 1. family revocations: PRIMARY KEY gains effective_at (a re-added member
--    can be removed again; an exact retry is still the #861 no-op).
-- 2. the family widening plane: federation_family_membership_widenings, the
--    mirror of the community one (V151 + V153's cosignatures).

-- ─── 1. family revocations ─────────────────────────────────────────────
DO $$
DECLARE c RECORD;
BEGIN
    FOR c IN
        SELECT con.conname
          FROM pg_constraint con
          JOIN pg_class      rel ON rel.oid = con.conrelid
          JOIN pg_namespace  nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = 'cirislens'
           AND rel.relname = 'federation_family_membership_revocations'
           AND con.contype = 'p'
    LOOP
        EXECUTE format('ALTER TABLE cirislens.federation_family_membership_revocations DROP CONSTRAINT %I', c.conname);
    END LOOP;
END $$;
ALTER TABLE cirislens.federation_family_membership_revocations
    ADD PRIMARY KEY (family_key_id, removed_identity_key_id, effective_at);

-- ─── 2. the family widening plane ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS cirislens.federation_family_membership_widenings (
    family_key_id             TEXT NOT NULL
        REFERENCES cirislens.federation_families(family_key_id),
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
    cosignatures              JSONB NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (family_key_id, member_key_id, effective_at)
);
CREATE INDEX IF NOT EXISTS federation_family_membership_widenings_effective
    ON cirislens.federation_family_membership_widenings (effective_at);
CREATE INDEX IF NOT EXISTS federation_family_membership_widenings_by_member
    ON cirislens.federation_family_membership_widenings (member_key_id);
CREATE INDEX IF NOT EXISTS federation_family_membership_widenings_admitted
    ON cirislens.federation_family_membership_widenings
       (admitted_at, family_key_id, member_key_id, effective_at);
