-- V121 (CIRISPersist#622) — `attestation_id` becomes TEXT on Postgres, so the
-- column can hold the ids the genesis ceremony actually SIGNED.
--
-- ── THE BREAK ────────────────────────────────────────────────────────────────
-- The baked production trust root (`src/federation/genesis/canonical_seed.json`)
-- carries three symbolic attestation ids inside its SIGNED envelope:
--
--     genesis-charter
--     genesis-grant:ciris-canonical-1-d7bdeu223k
--     genesis-lifecycle
--
-- `federation_attestations.attestation_id` was `UUID PRIMARY KEY` (V004:198), so
-- the driver refused the write before any persist logic ran:
--
--     invalid argument: attestation_id is not a valid UUID:
--       invalid character: found `g` at 0        -- the `g` of `genesis-charter`
--
-- Stage 1 (baked trust root) aborted and the embedding agent died. **Every
-- Postgres-backed node failed genesis; every SQLite node was immune**, because
-- SQLite has no `uuid` type. Same binary, same constant, same value. Two
-- production agents crash-looped 151 and 223 times with no operator remedy
-- (CIRISServer#381 / CIRISAgent#1020).
--
-- ── WHY RELAX THE COLUMN RATHER THAN FIX THE IDS ─────────────────────────────
-- The ids sit inside the ceremony envelope covered by `scrub_signature_classical`
-- (88 B64), `scrub_signature_pqc` (4412 B64) and `original_content_hash`.
-- Renaming them invalidates the production trust root, which took four mints and
-- two holders with hardware keys to produce.
--
-- Worse, that remedy INVERTS the failure. It was implemented downstream and
-- reverted: with UUID ids, `capability_roots_to_trusted_root` stops resolving
-- against the baked seed on EVERY backend, SQLite included — turning a loud,
-- Postgres-only outage into a quiet, fleet-wide trust-root loss.
-- `tests/genesis_bundle_validate.rs` going 3/6 red is the only reason it did not
-- ship.
--
-- ── THIS REMOVES A BACKEND ASYMMETRY; IT DOES NOT CREATE ONE ─────────────────
-- SQLite has typed this column `TEXT PRIMARY KEY` since V004
-- (`migrations/sqlite/lens/V004__federation_directory.sql:69`), as has V012's
-- twin. Postgres was the outlier. TEXT attestation ids are also already
-- precedent in this schema: V071 types `attestation_id TEXT NOT NULL PRIMARY
-- KEY` in three tables, and V109 documents a deliberate TEXT
-- `source_attestation_id`.
--
-- So this is a POSTGRES-ONLY migration, and there is deliberately no SQLite
-- counterpart — see `docs/` and the #574 note about the two DB arms differing in
-- strictness. Asserting a matching SQLite migration exists is the mistake to
-- avoid here.
--
-- ── LOSSLESS, AND WHAT IT COSTS ──────────────────────────────────────────────
-- `uuid::text` is total: every stored UUID has a canonical 36-char hyphenated
-- form, so existing rows keep their exact values and nothing is re-signed. No
-- bundle bytes change, no signature is recomputed, no holder is involved.
--
-- COST, stated because it is the operator-visible part: `ALTER COLUMN … TYPE`
-- takes an ACCESS EXCLUSIVE lock and REWRITES each table. On the reporting
-- node's ~3.2k rows that is instantaneous; on a large deployment it is a real
-- write-blocking window. Run it in a maintenance window if the attestation
-- tables are big.
--
-- The two FK columns MUST move in the same transaction: PostgreSQL requires a
-- foreign key's type to match its referent, so altering the primary key alone
-- fails. Constraints are discovered from the catalog rather than named
-- literally, because their auto-generated names are not guaranteed.

-- ── 1. drop the FKs that pin the referent's type ─────────────────────────────
DO $$
DECLARE
    c RECORD;
BEGIN
    FOR c IN
        SELECT con.conname, rel.relname
          FROM pg_constraint con
          JOIN pg_class      rel ON rel.oid = con.conrelid
          JOIN pg_namespace  nsp ON nsp.oid = rel.relnamespace
          JOIN pg_class      fre ON fre.oid = con.confrelid
         WHERE con.contype = 'f'
           AND nsp.nspname = 'cirislens'
           AND fre.relname = 'federation_attestations'
    LOOP
        EXECUTE format('ALTER TABLE cirislens.%I DROP CONSTRAINT %I',
                       c.relname, c.conname);
    END LOOP;
END $$;

-- ── 2. relax the primary key and both referring columns ──────────────────────
ALTER TABLE cirislens.federation_attestations
    ALTER COLUMN attestation_id TYPE TEXT USING attestation_id::text;

-- V004 gave the column `DEFAULT gen_random_uuid()`, which returns `uuid`. Keep a
-- server-side default so existing INSERTs that omit the id still work, but cast
-- it to the column's new type rather than leaving a type mismatch behind.
ALTER TABLE cirislens.federation_attestations
    ALTER COLUMN attestation_id SET DEFAULT gen_random_uuid()::text;

ALTER TABLE cirislens.attestation_subjects
    ALTER COLUMN attestation_id TYPE TEXT USING attestation_id::text;

ALTER TABLE cirislens.identity_canonical_binding
    ALTER COLUMN binding_attestation_id TYPE TEXT USING binding_attestation_id::text;

-- NOT TOUCHED: `cirisnode.promotion_attestations.attestation_id` stays `uuid`.
--
-- An earlier draft relaxed it too, reasoning it was "the same class waiting to
-- happen". That was scope creep past the reported defect, and the code says
-- otherwise: `src/cirisnode/postgres.rs::parse_id` documents a DELIBERATE UUID
-- discipline for that surface ("expected UUID", with a note that ULIDs must be
-- converted client-side), and the genesis bundle never writes a promotion
-- attestation. Relaxing it broke nothing but `put_promotion_attestation`, which
-- correctly binds a parsed `Uuid`.
--
-- If a symbolic id ever needs to reach that table, relax the column AND
-- `parse_id` together, as one deliberate change with its own witness.

-- ── 3. restore the FKs with their original delete semantics ──────────────────
-- V106: projection rows die with their parent.
ALTER TABLE cirislens.attestation_subjects
    ADD CONSTRAINT attestation_subjects_attestation_id_fkey
    FOREIGN KEY (attestation_id)
    REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE CASCADE;

-- V056: a binding whose establishing row is deleted becomes "inferred", not gone.
ALTER TABLE cirislens.identity_canonical_binding
    ADD CONSTRAINT identity_canonical_binding_binding_attestation_id_fkey
    FOREIGN KEY (binding_attestation_id)
    REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;
