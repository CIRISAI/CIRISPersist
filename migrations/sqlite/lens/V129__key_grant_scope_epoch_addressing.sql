-- V129 — key_grant scope/epoch addressing: one mechanism, N values
-- (v34.0.0, CIRISPersist#704, CIRISEdge#492, SQLite).
--
-- Mirrors migrations/postgres/lens/V129__key_grant_scope_epoch_addressing.sql.
--
-- V054 gave `subject_kind = 'key_grant'` ONE addressing mode: a wrapped DEK
-- bound to a recipient over a content SHA-256. V064 added a SECOND —
-- `(stream_id, epoch)` — for the streaming epoch-key cascade, and widened the
-- key_grant asymmetry rule into a two-way XOR: content-addressed OR
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
-- the ones the rule stops covering when it is assembled a branch at a time.
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
-- `key_grant_scope_kind` therefore has NO closed-value constraint,
-- deliberately. Pinning `IN ('stream', 'transit')` here would re-import the
-- exact cost the rename removes — a schema migration per scope kind — while
-- buying nothing the write door does not already buy: the admission path knows
-- the kinds it resolves and refuses the ones it does not. What the schema owes
-- this column is that it is present exactly when the other two are, and that is
-- what the triggers below say.
--
-- SQLITE HAS NO ALTER-A-CHECK AND NO ALTER-A-TRIGGER, so the postgres CHECK is
-- carried here by the BEFORE INSERT / BEFORE UPDATE trigger pair V054
-- introduced and V064 last rewrote. Their `WHEN` clause is the INVERSE
-- predicate — it fires, and ABORTs, exactly when a row VIOLATES the rule — so
-- both are dropped and recreated over the new column set.
--
-- NOT PURE-ADDITIVE, in two ways. The columns are RENAMED, so every reader
-- moves with them (src/cirisnode/sqlite.rs and src/cirisnode/postgres.rs both
-- name the old columns in INSERT and lookup SQL); and the asymmetry triggers
-- are dropped and recreated with the wider rule, exactly as V064 did to V054's.
--
-- EXISTING ROWS. This repo has not shipped live streaming key_grants, so the
-- expected carry is zero rows. The migration is written to be correct anyway:
-- SQLite 3.25+ `ALTER TABLE … RENAME COLUMN` moves the data in place with no
-- table rebuild, and the backfill below stamps `scope_kind = 'stream_epoch'` on any
-- row that WAS stream-addressed — the only kind a v064-era row can be.
--
-- STATEMENT ORDER IS LOAD-BEARING HERE, more than on the postgres side:
--
--   * the triggers are dropped FIRST. SQLite's RENAME COLUMN rewrites every
--     schema object that references the column, including trigger bodies — but
--     it does NOT rewrite the text inside the `RAISE(ABORT, '…')` string
--     literal, so a surviving V064 trigger would carry a diagnostic naming
--     columns that no longer exist. They are being replaced regardless;
--     dropping them before the rename also means the rename has nothing to
--     reparse.
--   * the backfill UPDATE runs while NO update trigger exists. If the new
--     BEFORE UPDATE trigger were already in place, the statement that sets
--     `scope_kind` would be evaluated against a row whose `scope_kind` is still
--     NULL at the moment the trigger's WHEN is checked — a row that satisfies
--     NEITHER branch — and the backfill would ABORT the migration it is part
--     of. This is the whole reason the trigger recreation is step 6 and not
--     step 3.
--
-- The takedown_notice triggers are a SEPARATE pair and are left untouched.

-- 1. Drop the V064 partial index and the V064 asymmetry triggers before the
--    rename. The index name would otherwise survive the rename and describe a
--    stream pair that is no longer there.
DROP INDEX IF EXISTS contributions_key_grant_stream_epoch;

DROP TRIGGER IF EXISTS cirisnode_contributions_key_grant_asymmetry_ins;
DROP TRIGGER IF EXISTS cirisnode_contributions_key_grant_asymmetry_upd;

-- 2. Carry the two addressing columns to their general names. RENAME moves the
--    data with no table rebuild and preserves the declared types (TEXT /
--    INTEGER) the postgres twin also declares (TEXT / BIGINT).
ALTER TABLE cirisnode_contributions
    RENAME COLUMN key_grant_stream_id TO key_grant_scope_id;

ALTER TABLE cirisnode_contributions
    RENAME COLUMN key_grant_stream_epoch TO key_grant_epoch;

-- 3. The new discriminator. Nullable, so `ALTER TABLE … ADD COLUMN` lands it in
--    place with no table rebuild; it is populated exactly in branch (b), which
--    the triggers in step 6 are what actually enforce.
ALTER TABLE cirisnode_contributions
    ADD COLUMN key_grant_scope_kind TEXT;

-- 4. Backfill, with no update trigger installed (see the header). Every row
--    that was scope-addressed before this migration was stream-addressed,
--    because stream/epoch was the only mode V064 admitted.
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
UPDATE cirisnode_contributions
    SET key_grant_scope_kind = 'stream_epoch'
    WHERE key_grant_scope_id IS NOT NULL
      AND key_grant_scope_kind IS NULL;

-- 5. Recreate the asymmetry triggers over the new column set. The `WHEN` is the
--    inverse of the postgres CHECK — it matches the rows the CHECK would
--    REJECT:
--      key_grant rows must have recipient NOT NULL AND exactly one addressing
--      mode (content XOR scope-epoch, and the scope-epoch branch demands all
--      THREE scope columns together); non-key_grant rows must leave recipient
--      + scope_kind + scope_id + epoch all NULL.
--
--    A half-addressed grant — scope_id with no kind, or a kind with no epoch —
--    satisfies neither branch and is refused outright, which is the property
--    that keeps "which scope is this DEK for" from ever being an inference.
CREATE TRIGGER cirisnode_contributions_key_grant_asymmetry_ins
    BEFORE INSERT ON cirisnode_contributions
    FOR EACH ROW
    WHEN (
        (NEW.subject_kind = 'key_grant'
            AND NOT (
                NEW.key_grant_recipient_key_id IS NOT NULL
                AND (
                    (NEW.media_content_sha256 IS NOT NULL
                        AND NEW.key_grant_scope_kind IS NULL
                        AND NEW.key_grant_scope_id IS NULL
                        AND NEW.key_grant_epoch IS NULL)
                    OR
                    (NEW.key_grant_scope_kind IS NOT NULL
                        AND NEW.key_grant_scope_id IS NOT NULL
                        AND NEW.key_grant_epoch IS NOT NULL
                        AND NEW.media_content_sha256 IS NULL)
                )
            ))
        OR
        (NEW.subject_kind <> 'key_grant'
            AND (NEW.key_grant_recipient_key_id IS NOT NULL
                 OR NEW.key_grant_scope_kind IS NOT NULL
                 OR NEW.key_grant_scope_id IS NOT NULL
                 OR NEW.key_grant_epoch IS NOT NULL))
    )
    BEGIN
        SELECT RAISE(ABORT, 'cirisnode_contributions: key_grant subject_kind requires key_grant_recipient_key_id + exactly one addressing mode (content-addressed: media_content_sha256; or scope-epoch-addressed: key_grant_scope_kind + key_grant_scope_id + key_grant_epoch, all three); other subject_kinds must leave key_grant_recipient_key_id, key_grant_scope_kind, key_grant_scope_id, key_grant_epoch NULL');
    END;

CREATE TRIGGER cirisnode_contributions_key_grant_asymmetry_upd
    BEFORE UPDATE ON cirisnode_contributions
    FOR EACH ROW
    WHEN (
        (NEW.subject_kind = 'key_grant'
            AND NOT (
                NEW.key_grant_recipient_key_id IS NOT NULL
                AND (
                    (NEW.media_content_sha256 IS NOT NULL
                        AND NEW.key_grant_scope_kind IS NULL
                        AND NEW.key_grant_scope_id IS NULL
                        AND NEW.key_grant_epoch IS NULL)
                    OR
                    (NEW.key_grant_scope_kind IS NOT NULL
                        AND NEW.key_grant_scope_id IS NOT NULL
                        AND NEW.key_grant_epoch IS NOT NULL
                        AND NEW.media_content_sha256 IS NULL)
                )
            ))
        OR
        (NEW.subject_kind <> 'key_grant'
            AND (NEW.key_grant_recipient_key_id IS NOT NULL
                 OR NEW.key_grant_scope_kind IS NOT NULL
                 OR NEW.key_grant_scope_id IS NOT NULL
                 OR NEW.key_grant_epoch IS NOT NULL))
    )
    BEGIN
        SELECT RAISE(ABORT, 'cirisnode_contributions: key_grant subject_kind requires key_grant_recipient_key_id + exactly one addressing mode (content-addressed: media_content_sha256; or scope-epoch-addressed: key_grant_scope_kind + key_grant_scope_id + key_grant_epoch, all three); other subject_kinds must leave key_grant_recipient_key_id, key_grant_scope_kind, key_grant_scope_id, key_grant_epoch NULL');
    END;

-- 6. The per-scope-epoch grant lookup, generalized from V064's
--    per-stream-epoch one. `scope_kind` leads because every read knows which
--    scope it is resolving — a streaming reader never wants transit rows — so
--    the index prefix is also the partition. Partial on `scope_id IS NOT NULL`
--    for the same reason V064's was: content-addressed grants are the majority
--    shape and have nothing to contribute to this index.
CREATE INDEX IF NOT EXISTS contributions_key_grant_scope_epoch
    ON cirisnode_contributions (key_grant_scope_kind, key_grant_scope_id, key_grant_epoch)
    WHERE key_grant_scope_id IS NOT NULL;
