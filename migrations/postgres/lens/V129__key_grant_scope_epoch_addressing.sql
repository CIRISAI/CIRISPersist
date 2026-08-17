-- V129 — key_grant scope/epoch addressing: one mechanism, N values
-- (v34.0.0, CIRISPersist#704, CIRISEdge#492, PostgreSQL).
--
-- Mirrored by migrations/sqlite/lens/V129__key_grant_scope_epoch_addressing.sql.
--
-- V054 gave `subject_kind = 'key_grant'` ONE addressing mode: a wrapped DEK
-- bound to a recipient over a content SHA-256. V064 added a SECOND —
-- `(stream_id, epoch)` — for the streaming epoch-key cascade, and widened the
-- cross-column CHECK into a two-way XOR: content-addressed OR
-- stream/epoch-addressed, never both, never neither.
--
-- CIRISEdge#492 now needs a THIRD thing addressed: transit membership. And
-- transit membership is not a new SHAPE. It is an `(id, epoch)` pair with
-- exactly one grant set per epoch, re-keyed when the membership changes —
-- structurally the same object as the streaming epoch cascade, which is an
-- `(id, epoch)` pair with exactly one grant set per epoch, re-keyed when the
-- stream rolls. The same predicate serves both because there is only one
-- predicate to serve.
--
-- WHY THIS RENAME RATHER THAN TWO MORE COLUMNS. The alternative — adding
-- `key_grant_transit_id` / `key_grant_transit_epoch` beside the stream pair —
-- turns a two-way XOR into a three-way one. That is the shape that does not
-- stop growing: every future scope adds a branch to a predicate whose
-- correctness is checked by reading all of it at once, and the fourth branch is
-- written by someone who has to re-derive what the first three meant. Worse,
-- an N-way XOR is where the mutually-exclusive property quietly dies — the
-- branch pairs nobody wrote down (transit id set AND stream id set) are exactly
-- the ones a CHECK stops covering when it is assembled a branch at a time.
--
-- Generalizing the columns instead keeps the XOR at TWO branches permanently:
--
--   (a) content-addressed:      media_content_sha256 NOT NULL, scope cols NULL
--   (b) scope-epoch-addressed:  scope_kind + scope_id + epoch ALL NOT NULL,
--                               media_content_sha256 NULL
--
-- Streaming and transit are two VALUES of `key_grant_scope_kind` inside branch
-- (b), not two branches. The next scope after transit is a third value and
-- needs no migration at all — which is the actual point: this cut removes the
-- pressure to ever add a third addressing CATEGORY, because the category the
-- substrate has is "addressed by an (id, epoch) pair" and that is already
-- general.
--
-- `key_grant_scope_kind` therefore has NO closed-value CHECK, deliberately.
-- Pinning `IN ('stream', 'transit')` here would re-import the exact cost the
-- rename removes — a schema migration per scope kind — while buying nothing the
-- write door does not already buy: the admission path knows the kinds it
-- resolves and refuses the ones it does not. What the schema owes this column
-- is that it is present exactly when the other two are, and that is what the
-- CHECK below says.
--
-- NOT PURE-ADDITIVE, in two ways. The columns are RENAMED, so every reader
-- moves with them (src/cirisnode/postgres.rs and src/cirisnode/sqlite.rs both
-- name the old columns in INSERT and lookup SQL); and the
-- `contributions_key_grant_columns_match_subject_kind` CHECK is dropped and
-- re-added with the wider rule, exactly as V064 did to V054's.
--
-- EXISTING ROWS. This repo has not shipped live streaming key_grants, so the
-- expected carry is zero rows. The migration is written to be correct anyway:
-- `RENAME COLUMN` moves the data in place with no copy and no rewrite, and the
-- backfill below stamps `scope_kind = 'stream_epoch'` on any row that WAS
-- stream-addressed — the only kind a v064-era row can be. The backfill runs
-- BEFORE the new CHECK is added, because `ADD CONSTRAINT` validates existing
-- rows and a carried row with a NULL `scope_kind` would fail branch (b).
--
-- THE RENAMES ARE TOP-LEVEL STATEMENTS, not wrapped in the `DO $$ … IF EXISTS`
-- guard V064 uses for its constraint swap. Two reasons, and the second is the
-- load-bearing one: refinery records applied versions in
-- `ciris_persist_schema_history`, so this file runs exactly once per database
-- and the guard would be protecting against nothing; and the schema-parity gate
-- (src/store/schema_parity.rs, CIRISPersist#670) replays this DDL textually to
-- compare the two dialect trees. It reads `ALTER TABLE … RENAME COLUMN` only at
-- statement level — a rename buried inside a `DO` block is INVISIBLE to it, and
-- the postgres tree would appear to still declare `key_grant_stream_id` while
-- sqlite declared `key_grant_scope_id`. The guard would have bought
-- idempotency the runner already provides at the price of blinding the gate
-- that checks the two trees still agree.
--
-- The takedown_notice constraint
-- (`contributions_takedown_columns_match_subject_kind`) is a SEPARATE named
-- constraint and is left untouched.

-- 1. Drop the V064 partial index BEFORE the rename. Postgres would rewrite the
--    index definition to follow the renamed columns but KEEP the old name, so
--    the schema would carry an index called `…_stream_epoch` over
--    `(scope_id, epoch)` — a name that lies about what it indexes.
DROP INDEX IF EXISTS cirisnode.contributions_key_grant_stream_epoch;

-- 2. Carry the two addressing columns to their general names. RENAME moves the
--    data with no copy and preserves the types (TEXT / BIGINT) and the
--    nullability the sqlite twin also declares.
ALTER TABLE cirisnode.contributions
    RENAME COLUMN key_grant_stream_id TO key_grant_scope_id;

ALTER TABLE cirisnode.contributions
    RENAME COLUMN key_grant_stream_epoch TO key_grant_epoch;

-- 3. The new discriminator. Nullable: it is populated exactly in branch (b),
--    which the CHECK in step 5 is what actually enforces.
ALTER TABLE cirisnode.contributions
    ADD COLUMN IF NOT EXISTS key_grant_scope_kind TEXT NULL;

-- 4. Backfill. Every row that was scope-addressed before this migration was
--    stream-addressed, because stream/epoch was the only mode V064 admitted. Must
--    precede the ADD CONSTRAINT below, which validates existing rows.
-- TOKEN VOCABULARY (v34.0.0, #704) — this column holds EXACTLY the strings
-- `KeyGrantScope::as_str()` emits: `stream_epoch`, `transit_membership`. NOT
-- shortened forms.
--
-- An earlier draft of this migration backfilled `'stream'` while the Rust write
-- path stamped `'stream_epoch'`, so a carried row and a newly written row would
-- have described the same thing with two different tokens. Nothing would have
-- failed: the column is deliberately unconstrained, so both insert happily —
-- and any later read filtering on `scope_kind` would have silently skipped the
-- carried rows. A missing row is not an error anywhere; it just looks like the
-- grant was never issued.
--
-- One vocabulary, and it is the one the code emits. If these ever need to
-- diverge, the mapping belongs in Rust beside `as_str()`, never as a second
-- spelling agreed by hand across a migration and a writer.
UPDATE cirisnode.contributions
    SET key_grant_scope_kind = 'stream_epoch'
    WHERE key_grant_scope_id IS NOT NULL
      AND key_grant_scope_kind IS NULL;

-- 5. Replace the key_grant cross-column CHECK. Same DROP-IF-EXISTS + ADD guard
--    pattern V054/V064 use. The rule, still TWO branches:
--      subject_kind = 'key_grant'  <=>  recipient NOT NULL AND exactly one
--      addressing mode holds:
--        (a) content-addressed:
--              media_content_sha256 NOT NULL
--              AND key_grant_scope_kind IS NULL
--              AND key_grant_scope_id IS NULL
--              AND key_grant_epoch IS NULL
--        (b) scope-epoch-addressed:
--              key_grant_scope_kind NOT NULL
--              AND key_grant_scope_id NOT NULL
--              AND key_grant_epoch NOT NULL
--              AND media_content_sha256 IS NULL
--      subject_kind <> 'key_grant'  =>  recipient, scope_kind, scope_id,
--      epoch ALL NULL.
--
--    Branch (b) demands all THREE scope columns together. A half-addressed
--    grant — scope_id with no kind, or a kind with no epoch — is refused by
--    both branches and so is refused outright, which is the property that
--    keeps "which scope is this DEK for" from ever being an inference.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'contributions_key_grant_columns_match_subject_kind'
          AND conrelid = 'cirisnode.contributions'::regclass
    ) THEN
        ALTER TABLE cirisnode.contributions
            DROP CONSTRAINT contributions_key_grant_columns_match_subject_kind;
    END IF;

    ALTER TABLE cirisnode.contributions
        ADD CONSTRAINT contributions_key_grant_columns_match_subject_kind
            CHECK (
                (subject_kind = 'key_grant'
                  AND key_grant_recipient_key_id IS NOT NULL
                  AND (
                      -- (a) content-addressed
                      (media_content_sha256 IS NOT NULL
                          AND key_grant_scope_kind IS NULL
                          AND key_grant_scope_id IS NULL
                          AND key_grant_epoch IS NULL)
                      OR
                      -- (b) scope-epoch-addressed
                      (key_grant_scope_kind IS NOT NULL
                          AND key_grant_scope_id IS NOT NULL
                          AND key_grant_epoch IS NOT NULL
                          AND media_content_sha256 IS NULL)
                  ))
                OR
                (subject_kind <> 'key_grant'
                  AND key_grant_recipient_key_id IS NULL
                  AND key_grant_scope_kind IS NULL
                  AND key_grant_scope_id IS NULL
                  AND key_grant_epoch IS NULL)
            );
END$$;

-- 6. The per-scope-epoch grant lookup, generalized from V064's
--    per-stream-epoch one. `scope_kind` leads because every read knows which
--    scope it is resolving — a streaming reader never wants transit rows — so
--    the index prefix is also the partition. Partial on `scope_id IS NOT NULL`
--    for the same reason V064's was: content-addressed grants are the majority
--    shape and have nothing to contribute to this index.
CREATE INDEX IF NOT EXISTS contributions_key_grant_scope_epoch
    ON cirisnode.contributions (key_grant_scope_kind, key_grant_scope_id, key_grant_epoch)
    WHERE key_grant_scope_id IS NOT NULL;

-- 7. Re-comment. Postgres carries a column COMMENT across a rename, so without
--    this the two renamed columns would still describe themselves as the
--    streaming pair.
COMMENT ON COLUMN cirisnode.contributions.key_grant_scope_kind IS
    'v34.0.0 (CIRISPersist#704, CIRISEdge#492) — populated iff subject_kind = ''key_grant'' AND scope-epoch-addressed (media_content_sha256 NULL). Names WHICH addressing scope key_grant_scope_id is an id in: ''stream'' (the streaming epoch-key cascade) or ''transit'' (transit membership). Deliberately NOT a closed enum in the schema — a new scope kind is a new value, not a new migration.';

COMMENT ON COLUMN cirisnode.contributions.key_grant_scope_id IS
    'v34.0.0 (CIRISPersist#704) — was key_grant_stream_id through V064..V128. Populated iff subject_kind = ''key_grant'' AND scope-epoch-addressed. The id, WITHIN key_grant_scope_kind, that the epoch-DEK is scoped to.';

COMMENT ON COLUMN cirisnode.contributions.key_grant_epoch IS
    'v34.0.0 (CIRISPersist#704) — was key_grant_stream_epoch through V064..V128. Populated iff subject_kind = ''key_grant'' AND scope-epoch-addressed. The epoch within (key_grant_scope_kind, key_grant_scope_id) the wrapped DEK covers; one grant set per epoch.';
