-- V064 — key_grant stream/epoch addressing, SQLite dialect
-- (CIRISPersist#142, Cut C3a; CEG 0.15 §10.5.3 RC1-1c).
--
-- Postgres parity (postgres/lens/V064):
--   - cirisnode_contributions gains two nullable addressing columns
--     (key_grant_stream_id, key_grant_stream_epoch).
--   - The key_grant cross-column rule (enforced here by the V054
--     BEFORE INSERT/UPDATE triggers, since SQLite has no ALTER TABLE …
--     ADD/DROP CONSTRAINT) is widened to admit BOTH addressing modes:
--     content-addressed XOR stream/epoch-addressed.
--
-- SQLite can't ALTER a trigger, so we DROP + recreate both key_grant
-- asymmetry triggers with the extended RAISE(ABORT) condition. The two
-- new columns are nullable, so `ALTER TABLE … ADD COLUMN` lands them
-- in place — NO table rebuild needed.
--
-- The takedown_notice triggers are a SEPARATE pair and are left
-- untouched.

-- 1. New nullable addressing columns (no table rebuild — ALTER ADD
--    COLUMN works for nullable cols).
ALTER TABLE cirisnode_contributions
    ADD COLUMN key_grant_stream_id TEXT;

ALTER TABLE cirisnode_contributions
    ADD COLUMN key_grant_stream_epoch INTEGER;

-- 2. Drop the V054 key_grant asymmetry triggers and recreate them with
--    the widened rule. The trigger ABORTs when a row VIOLATES the rule
--    (the inverse of the PG CHECK predicate):
--      key_grant rows must have recipient NOT NULL AND exactly one
--      addressing mode (content XOR stream/epoch); non-key_grant rows
--      must leave recipient + stream_id + stream_epoch all NULL.
DROP TRIGGER IF EXISTS cirisnode_contributions_key_grant_asymmetry_ins;
DROP TRIGGER IF EXISTS cirisnode_contributions_key_grant_asymmetry_upd;

CREATE TRIGGER cirisnode_contributions_key_grant_asymmetry_ins
    BEFORE INSERT ON cirisnode_contributions
    FOR EACH ROW
    WHEN (
        (NEW.subject_kind = 'key_grant'
            AND NOT (
                NEW.key_grant_recipient_key_id IS NOT NULL
                AND (
                    (NEW.media_content_sha256 IS NOT NULL
                        AND NEW.key_grant_stream_id IS NULL
                        AND NEW.key_grant_stream_epoch IS NULL)
                    OR
                    (NEW.key_grant_stream_id IS NOT NULL
                        AND NEW.key_grant_stream_epoch IS NOT NULL
                        AND NEW.media_content_sha256 IS NULL)
                )
            ))
        OR
        (NEW.subject_kind <> 'key_grant'
            AND (NEW.key_grant_recipient_key_id IS NOT NULL
                 OR NEW.key_grant_stream_id IS NOT NULL
                 OR NEW.key_grant_stream_epoch IS NOT NULL))
    )
    BEGIN
        SELECT RAISE(ABORT, 'cirisnode_contributions: key_grant subject_kind requires key_grant_recipient_key_id + exactly one addressing mode (content-addressed: media_content_sha256; or stream/epoch-addressed: key_grant_stream_id + key_grant_stream_epoch); other subject_kinds must leave key_grant_recipient_key_id, key_grant_stream_id, key_grant_stream_epoch NULL');
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
                        AND NEW.key_grant_stream_id IS NULL
                        AND NEW.key_grant_stream_epoch IS NULL)
                    OR
                    (NEW.key_grant_stream_id IS NOT NULL
                        AND NEW.key_grant_stream_epoch IS NOT NULL
                        AND NEW.media_content_sha256 IS NULL)
                )
            ))
        OR
        (NEW.subject_kind <> 'key_grant'
            AND (NEW.key_grant_recipient_key_id IS NOT NULL
                 OR NEW.key_grant_stream_id IS NOT NULL
                 OR NEW.key_grant_stream_epoch IS NOT NULL))
    )
    BEGIN
        SELECT RAISE(ABORT, 'cirisnode_contributions: key_grant subject_kind requires key_grant_recipient_key_id + exactly one addressing mode (content-addressed: media_content_sha256; or stream/epoch-addressed: key_grant_stream_id + key_grant_stream_epoch); other subject_kinds must leave key_grant_recipient_key_id, key_grant_stream_id, key_grant_stream_epoch NULL');
    END;

-- 3. Partial index for the later per-stream-epoch grant lookup.
CREATE INDEX IF NOT EXISTS contributions_key_grant_stream_epoch
    ON cirisnode_contributions (key_grant_stream_id, key_grant_stream_epoch)
    WHERE key_grant_stream_id IS NOT NULL;
