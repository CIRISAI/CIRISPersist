-- V182 — admit 'affiliations' into federation_group_versions.cohort (Postgres dialect)
--        v54.0.0 (CIRISPersist#1034, CC 4.4.3.2.8).
--
-- V089 created the supersede history with
-- `CHECK (cohort IN ('family', 'community'))`, and no later migration widened
-- it. `supersede_affiliations` records the prior version under the
-- `affiliations` discriminator (CC 4.4.3.2.8: the version chain stays
-- separable per tier), so every supersession of an affiliation was refused by
-- the CHECK on both SQL backends. Only the memory backend, which has no CHECK,
-- had ever run it. Nothing is removed and no row changes.
--
-- V089 is not edited: a shipped migration is immutable as bytes. The inline
-- CHECK's generated name is looked up rather than assumed, then the widened
-- CHECK is added under a fixed name. Re-running this file is a no-op: the
-- lookup finds whichever cohort CHECK is present and replaces it with the same
-- definition.

DO $$
DECLARE
    conname_to_drop text;
BEGIN
    FOR conname_to_drop IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t     ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'cirislens'
          AND t.relname = 'federation_group_versions'
          AND c.contype = 'c'
          AND c.conkey = ARRAY[
                (SELECT a.attnum FROM pg_attribute a
                  WHERE a.attrelid = t.oid AND a.attname = 'cohort')
              ]::smallint[]
    LOOP
        EXECUTE format(
            'ALTER TABLE cirislens.federation_group_versions DROP CONSTRAINT %I',
            conname_to_drop);
    END LOOP;
END
$$;

ALTER TABLE cirislens.federation_group_versions
    ADD CONSTRAINT federation_group_versions_cohort_check
    CHECK (cohort IN ('family', 'community', 'affiliations'));
