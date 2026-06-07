-- V064 — key_grant stream/epoch addressing (CIRISPersist#142, Cut C3a;
-- CEG 0.15 §10.5.3 "RC1-1c — not pure-additive at the Persist
-- constraint layer"; FSD/V4_1_STREAMING_SUBSTRATE.md §4.4).
--
-- V054 landed the content-addressed `key_grant` shape: a
-- `subject_kind = 'key_grant'` row REQUIRES both `media_content_sha256`
-- AND `key_grant_recipient_key_id` NOT NULL. That binds a wrapped DEK
-- to a recipient over a content SHA-256.
--
-- The streaming epoch-key cascade (Cut C3b) addresses grants by
-- `(stream_id, epoch)` instead of by content SHA — a per-stream-epoch
-- DEK is wrapped to a recipient, with NO content SHA. The V054
-- constraint REJECTS that shape (it demands media_content_sha256 NOT
-- NULL for every key_grant). This migration extends the constraint so
-- the table admits BOTH addressing modes — content-addressed XOR
-- stream/epoch-addressed — and is therefore NOT pure-additive: the
-- existing `contributions_key_grant_columns_match_subject_kind`
-- constraint is dropped and re-added with the wider rule.
--
-- This cut is migration-ONLY. The stream-key_grant write path
-- (epoch-DEK generation + wrapping, payload changes) is Cut C3b. C3a
-- just makes the schema admit the new shape.
--
-- The takedown_notice constraint
-- (`contributions_takedown_columns_match_subject_kind`) is a SEPARATE
-- named constraint and is left untouched.

-- 1. New nullable addressing columns. Pure-additive at the column
--    layer; the constraint swap below is the non-additive part.
ALTER TABLE cirisnode.contributions
    ADD COLUMN IF NOT EXISTS key_grant_stream_id TEXT NULL;

ALTER TABLE cirisnode.contributions
    ADD COLUMN IF NOT EXISTS key_grant_stream_epoch BIGINT NULL;

-- 2. Replace the key_grant cross-column CHECK. Same DROP-IF-EXISTS +
--    ADD guard pattern V054/V056 use, so re-running the chain is
--    idempotent. New rule:
--      subject_kind = 'key_grant'  <=>  recipient NOT NULL AND exactly
--      one addressing mode holds:
--        (a) content-addressed:
--              media_content_sha256 NOT NULL
--              AND key_grant_stream_id IS NULL
--              AND key_grant_stream_epoch IS NULL
--        (b) stream/epoch-addressed:
--              key_grant_stream_id NOT NULL
--              AND key_grant_stream_epoch NOT NULL
--              AND media_content_sha256 IS NULL
--      subject_kind <> 'key_grant'  =>  recipient, stream_id,
--      stream_epoch ALL NULL.
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
                          AND key_grant_stream_id IS NULL
                          AND key_grant_stream_epoch IS NULL)
                      OR
                      -- (b) stream/epoch-addressed
                      (key_grant_stream_id IS NOT NULL
                          AND key_grant_stream_epoch IS NOT NULL
                          AND media_content_sha256 IS NULL)
                  ))
                OR
                (subject_kind <> 'key_grant'
                  AND key_grant_recipient_key_id IS NULL
                  AND key_grant_stream_id IS NULL
                  AND key_grant_stream_epoch IS NULL)
            );
END$$;

-- 3. Partial index for the later per-stream-epoch grant lookup
--    (Cut C3b reads grants by (stream_id, epoch)).
CREATE INDEX IF NOT EXISTS contributions_key_grant_stream_epoch
    ON cirisnode.contributions (key_grant_stream_id, key_grant_stream_epoch)
    WHERE key_grant_stream_id IS NOT NULL;

COMMENT ON COLUMN cirisnode.contributions.key_grant_stream_id IS
    'v4.1 (CIRISPersist#142 Cut C3a) — populated iff subject_kind = ''key_grant'' AND stream/epoch-addressed (media_content_sha256 NULL). The federation_streams stream_id the epoch-DEK is scoped to.';

COMMENT ON COLUMN cirisnode.contributions.key_grant_stream_epoch IS
    'v4.1 (CIRISPersist#142 Cut C3a) — populated iff subject_kind = ''key_grant'' AND stream/epoch-addressed. The epoch within key_grant_stream_id the wrapped DEK covers.';
