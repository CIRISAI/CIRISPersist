-- v13.3.0 (CIRISPersist#386) — a **constitutional family is keyless**: it is
-- constituted by its founder quorum (the founder signatures), NOT by owning a
-- registered key. The original inline FK
-- `federation_families.family_key_id REFERENCES federation_keys(key_id)`
-- encoded the false assumption "a family's own key is registered", which
-- blocked baking the HUMANITY_ACCORD family row (`humanity-accord` has no
-- keypair). Drop the FK; the REAL invariant — every MEMBER key_id is a
-- registered federation_keys row — moves to write-time validation in
-- `put_family` (applies to every family, constitutional or not).
--
-- Find + drop the FK by its real (auto-generated) name; there is exactly one
-- FK on the table (the family_key_id one). No child table references
-- federation_families, so this is non-destructive.
DO $$
DECLARE cname text;
BEGIN
    SELECT conname INTO cname
    FROM pg_constraint
    WHERE conrelid = 'cirislens.federation_families'::regclass
      AND contype = 'f';
    IF cname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE cirislens.federation_families DROP CONSTRAINT %I', cname);
    END IF;
END $$;
