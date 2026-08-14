-- V125 (CIRISPersist#622, sibling of V121) — `revocation_id` becomes TEXT on
-- Postgres, so the column can hold every value the public Rust type permits.
--
-- ── ORDERING, DELIBERATE ─────────────────────────────────────────────────────
-- Numbered V125, not V123, because CIRISPersist#655/#667 is landing V123
-- (`revocation_local_admission_instant`) and V124 (`accord_proposal_payload_index`)
-- into this same release, and **its V123 touches this same table**: it adds
-- `admitted_at` and creates
--
--     federation_revocations_admitted (admitted_at, revocation_id)
--
-- An `ALTER COLUMN … TYPE` rebuilds every index over the column, so this
-- migration must run AFTER that index exists or it will not rebuild it. Running
-- second is the only ordering that composes; it is stated here rather than left
-- to refinery's file ordering to arrange by accident.
--
-- The shape below follows V122, which already did `ALTER COLUMN … TYPE TEXT` on
-- this exact table (`revocation_envelope`), and V121, which did it for the
-- sibling id column.
--
-- ── THE BREAK ────────────────────────────────────────────────────────────────
-- `Revocation::revocation_id` is a plain `String` (`src/federation/types.rs`).
-- Nothing in the type, in `put_revocation`'s gates, or in the wire contract
-- constrains it to UUID shape. Memory stores whatever it is handed; SQLite has
-- typed the column `TEXT PRIMARY KEY` since V004.
--
-- Postgres typed it `UUID PRIMARY KEY` (V004:256), and the quorum-state child
-- inherited that type through its foreign key (V058:78). So the backend
-- production runs refused, at the DRIVER, before any persist logic:
--
--     invalid argument: revocation_id is not a valid UUID:
--       invalid character: found `g` at 0
--
-- A consumer passing a symbolic revocation id is admitted on two backends and
-- rejected on the third. There is no workaround available downstream except
-- "ids must be UUIDs, but only on postgres" — a persist quirk a caller has to
-- know about, which is precisely the class this project holds itself to fixing
-- rather than documenting.
--
-- ── THIS IS V121, ONE TABLE OVER ─────────────────────────────────────────────
-- V121 relaxed `attestation_id` for exactly this reason: the genesis ceremony
-- signs symbolic ids (`genesis-charter`,
-- `genesis-grant:ciris-canonical-1-d7bdeu223k`) that are not UUIDs, and every
-- Postgres-backed node failed genesis while every SQLite node was immune.
-- Same defect, same fix, same direction — REMOVING a backend asymmetry rather
-- than creating one. The finding came out of the CIRISPersist#670 schema-parity
-- gate, which compares the two migration trees' resulting column types and
-- names `uuid` against `TEXT` as a NARROWING rather than an encoding.
--
-- ── WHY BOTH TABLES, IN ONE MIGRATION ────────────────────────────────────────
-- `federation_revocation_quorum_state.revocation_id` is `UUID PRIMARY KEY
-- REFERENCES federation_revocations(revocation_id)`. PostgreSQL requires a
-- foreign key's type to match its referent, so altering the parent alone fails
-- outright. Fixing one and leaving the other would also leave the identical
-- finding open on the child, which is how a two-table defect becomes two
-- releases.
--
-- ── LOSSLESS ─────────────────────────────────────────────────────────────────
-- `uuid::text` is total: every stored UUID has a canonical 36-char hyphenated
-- form, so existing rows keep their exact values. `revocation_id` is NOT part
-- of `admission::revocation_binding`'s signed set and is not an input to
-- `compute_persist_row_hash`'s signature — nothing is re-signed, no envelope
-- bytes change, no holder is involved.
--
-- COST, stated because it is the operator-visible part: `ALTER COLUMN … TYPE`
-- takes an ACCESS EXCLUSIVE lock and rewrites the table. Revocation tables are
-- small on every deployment measured so far; on a large one, use a maintenance
-- window.
--
-- ── THE CURSOR: THIS REPAIRS AN EXISTING INCONSISTENCY ───────────────────────
-- Every read path that touches `revocation_id` was enumerated before cutting
-- this. There are five, and exactly one of them ORDERS or RANGES on the column:
-- the revocation `_since` cursor in `src/store/postgres.rs`, which today emits
--
--     WHERE   (revoked_at, revocation_id::text) < ($p_at, $p_id)
--     ORDER BY revoked_at DESC, revocation_id DESC
--
-- Note the asymmetry. **The WHERE clause casts to text and the ORDER BY does
-- not**, so with a `uuid` column the tie-break predicate compares text while
-- the sort compares UUIDs. Those are different orders, and a cursor whose
-- resume predicate disagrees with its own sort can skip a row at a `revoked_at`
-- tie and never serve it again — CIRISPersist#668's class, live on postgres
-- today and NOT on sqlite, which compares TEXT on both sides.
--
-- Making the column TEXT turns `revocation_id::text` into a no-op and puts the
-- predicate and the sort back on one order. So this is not "a change the
-- cursor survives"; it is a fix the cursor needed. The remaining nuance is
-- collation: postgres `text` sorts under the database's default collation while
-- SQLite sorts BINARY, so the two backends still tie-break differently for ids
-- that differ in case or punctuation. That is strictly closer than uuid-vs-text
-- and is filed rather than smuggled in here — the true fix is `COLLATE "C"` on
-- the index and the ORDER BY, which belongs with #668.
--
-- The other four paths are equality lookups (`WHERE revocation_id = $1`) and
-- projections (`SELECT revocation_id::text`), none of which change meaning.
--
-- ── INDEXES ──────────────────────────────────────────────────────────────────
-- Three, all rebuilt automatically by the type change: the V004 primary key,
-- V058's primary key on the quorum-state child, and V058's
-- `federation_revocation_quorum_state_pending (revocation_id, quorum_weight)`.
-- Plus #655's `federation_revocations_admitted` once that lands — see the
-- ordering note at the top. Nothing else in either migration tree indexes this
-- column.
--
-- ── POSTGRES-ONLY, ON PURPOSE ────────────────────────────────────────────────
-- There is deliberately no SQLite counterpart: SQLite has no `uuid` type and
-- has held `TEXT PRIMARY KEY` since V004. Asserting a matching SQLite migration
-- exists is the mistake V121 called out and this file repeats the warning.

-- ── 1. drop the FK that pins the referent's type ─────────────────────────────
-- Discovered from the catalog rather than named literally: auto-generated
-- constraint names are not guaranteed, and V058 did not name this one.
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
           AND fre.relname = 'federation_revocations'
           AND rel.relname = 'federation_revocation_quorum_state'
    LOOP
        EXECUTE format('ALTER TABLE cirislens.%I DROP CONSTRAINT %I',
                       c.relname, c.conname);
    END LOOP;
END $$;

-- ── 2. relax the primary key and the referring column ────────────────────────
ALTER TABLE cirislens.federation_revocations
    ALTER COLUMN revocation_id TYPE TEXT USING revocation_id::text;

-- V004 gave the column `DEFAULT gen_random_uuid()`, which returns `uuid`. Keep
-- a server-side default so an INSERT that omits the id still works, cast to the
-- column's new type — byte-for-byte the choice V121 made for `attestation_id`.
-- Consistency with that decision matters more than the decision: two id columns
-- in one schema that disagree about whether the server will mint for you is a
-- distinction nobody can hold in their head.
ALTER TABLE cirislens.federation_revocations
    ALTER COLUMN revocation_id SET DEFAULT gen_random_uuid()::text;

ALTER TABLE cirislens.federation_revocation_quorum_state
    ALTER COLUMN revocation_id TYPE TEXT USING revocation_id::text;

-- ── 3. restore the FK with its original delete semantics ─────────────────────
-- V058: the quorum bookkeeping dies with the revocation it tracks.
ALTER TABLE cirislens.federation_revocation_quorum_state
    ADD CONSTRAINT federation_revocation_quorum_state_revocation_id_fkey
    FOREIGN KEY (revocation_id)
    REFERENCES cirislens.federation_revocations(revocation_id) ON DELETE CASCADE;

COMMENT ON COLUMN cirislens.federation_revocations.revocation_id IS
    'v31.1.0 (CIRISPersist#622) — TEXT, not UUID. `Revocation::revocation_id` is a String and nothing constrains it to UUID shape; memory and SQLite have always stored any TEXT. Same relaxation V121 applied to attestation_id.';
