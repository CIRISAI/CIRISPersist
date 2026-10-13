-- V193 — a stream epoch's DEK may be caller-supplied (always kept), and a
-- room's stream is stream-keyed too. PostgreSQL dialect.
-- v55.0.0 (CIRISPersist#981, #977; CC 5.3.3.1, CC 5.1, CC 5.3.3.2.5).
--
-- SQLITE PARITY: migrations/sqlite/lens/V193__stream_epoch_dek_supplied_and_rooms.sql
-- (that file's header carries the reasoning; this one carries the DDL).
-- The V168 `cohort_scope` CHECKs are dropped by what they constrain (their
-- generated names are not assumed) and re-added widened to the room scopes.
DO $$
DECLARE c RECORD;
BEGIN
    FOR c IN
        SELECT conrelid::regclass AS tbl, conname
          FROM pg_constraint
         WHERE contype = 'c'
           AND conrelid IN ('cirislens.federation_stream_deks'::regclass,
                            'cirislens.federation_stream_dek_grants'::regclass)
           AND pg_get_constraintdef(oid) LIKE '%cohort_scope%'
    LOOP
        EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', c.tbl, c.conname);
    END LOOP;
END $$;

ALTER TABLE cirislens.federation_stream_deks
    ADD CONSTRAINT federation_stream_deks_cohort_scope_v193
        CHECK (cohort_scope IN ('self', 'family', 'community', 'affiliations')),
    ADD COLUMN supplied BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN room_epoch BIGINT CHECK (room_epoch IS NULL OR room_epoch >= 0),
    ADD COLUMN evicted_at TIMESTAMPTZ;

ALTER TABLE cirislens.federation_stream_dek_grants
    ADD CONSTRAINT federation_stream_dek_grants_cohort_scope_v193
        CHECK (cohort_scope IN ('self', 'family', 'community', 'affiliations'));
