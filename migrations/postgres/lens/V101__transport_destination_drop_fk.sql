-- V101 — CIRISPersist#416: drop the transport_destinations → federation_keys FK.
--        Postgres dialect. SQLite parity: sqlite/lens/V101.
--
-- V078 declared occurrence_key_id NOT NULL REFERENCES federation_keys(key_id)
-- "to keep an address from naming an unknown occurrence key." But #413 (V100)
-- made this table record ADVISORY bindings (CC 3.3.6.2, part_3 §1056/§1331): a
-- self-consistent announce whose signing key is NOT-yet-rooted and therefore
-- NOT in federation_keys. The FK rejects exactly the row admit-advisory must
-- record. The FK's guarantee is what admit-advisory supersedes; the replacement
-- correctness is the binding_provenance tag + routing-time preference (prefer
-- Rooted over Advisory; content gates on trust, CC 6 N1). Rooted keys are in
-- federation_keys anyway, so dropping the FK does not weaken them.
--
-- Drop the single FK on occurrence_key_id by its (deterministic, but resolved
-- dynamically to be name-agnostic) constraint name.

DO $$
DECLARE fk_name text;
BEGIN
    SELECT conname INTO fk_name
    FROM pg_constraint
    WHERE conrelid = 'cirislens.transport_destinations'::regclass
      AND contype = 'f'
    LIMIT 1;
    IF fk_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE cirislens.transport_destinations DROP CONSTRAINT %I', fk_name);
    END IF;
END $$;
