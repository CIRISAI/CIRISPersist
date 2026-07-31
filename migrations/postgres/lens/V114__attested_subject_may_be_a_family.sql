-- V114 — the attested subject may be a KEYLESS constitutional family
-- v24.0.0 (CIRISPersist#557)
--
-- SQLITE PARITY: migrations/sqlite/lens/V114__attested_subject_may_be_a_family.sql
-- (same constraint removed, same rule kept, same shared predicate enforcing it;
-- SQLite needs a table rebuild for it, Postgres has DROP CONSTRAINT.)
--
-- WHAT MOVES, AND WHY IT IS NOT A LOOSENING
-- -----------------------------------------
-- `federation_attestations.attested_key_id` carried
-- `REFERENCES cirislens.federation_keys(key_id)` (V004). SQLite declared the
-- same FK and the memory backend emulated it in code: **all three backends
-- enforced this rule**, and the rule — "you may not attest ABOUT an identifier
-- this node has never heard of" — is right and is KEPT.
--
-- What a schema FK cannot express is the one legitimate exception:
--
--   a CONSTITUTIONAL FAMILY is KEYLESS by doctrine (v13.3.0 dropped
--   `families.family_key_id`'s FK for exactly this reason — the family id is
--   an identifier, not a key; there is no seat to compromise, which is
--   precisely why it can be the durable name of a trust root).
--
-- #557's whole ask is that a node's `trust:accepts` edge NAME THE ACCORD rather
-- than whichever holder happened to sign the charter — i.e.
-- `delegates_to(node → humanity-accord)`, plus that family's charter and drill
-- rows. Every one of those has `attested_key_id = <family id>`, and a keyless
-- family has no `federation_keys` row to point at. Under this FK the family
-- root is not merely unimplemented, it is UNSTORABLE.
--
-- So the constraint is not deleted — it is LIFTED into
-- `check_attested_subject_admission` (src/federation/admission.rs), which
-- refuses any `attested_key_id` that resolves as NEITHER a registered
-- `federation_keys` row NOR a constitutional family this node already knows.
-- That is strictly narrower than "any string" and, unlike the FK, it is the
-- same predicate on memory, sqlite and postgres.
--
-- The FKs on `attesting_key_id` and `scrub_key_id` are DELIBERATELY KEPT: those
-- two identify SIGNERS, and a signer with no key record could not have signed.
--
-- Dropped by DISCOVERY, not by name. V004 declares the FK inline, so its name is
-- whatever Postgres generated (`federation_attestations_attested_key_id_fkey` on
-- every database we have seen). Looking it up in `pg_constraint` means a
-- deployment whose constraint was ever renamed — or restored from a dump under a
-- different name — is migrated correctly rather than silently left enforcing it,
-- which is exactly the failure mode this migration exists to end.

DO $$
DECLARE
    conname_to_drop text;
BEGIN
    SELECT c.conname INTO conname_to_drop
    FROM pg_constraint c
    JOIN pg_class t     ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = 'cirislens'
      AND t.relname = 'federation_attestations'
      AND c.contype = 'f'
      AND c.conkey = ARRAY[
            (SELECT a.attnum FROM pg_attribute a
              WHERE a.attrelid = t.oid AND a.attname = 'attested_key_id')
          ]::smallint[];

    IF conname_to_drop IS NOT NULL THEN
        EXECUTE format(
            'ALTER TABLE cirislens.federation_attestations DROP CONSTRAINT %I',
            conname_to_drop);
    END IF;
END
$$;
