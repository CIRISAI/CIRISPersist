-- V044 — `verification_source` discriminator on trace_events (sqlite).
-- Postgres counterpart at
-- migrations/postgres/lens/V044__trace_events_verification_source.sql
-- — same column, same CHECK set, same DEFAULT; see that file for the
-- CIRISPersist#91 rationale.
--
-- SQLite `ALTER TABLE ... ADD COLUMN` accepts a CHECK constraint and
-- a constant `DEFAULT`, so the column lands with both in one
-- statement. `signature_verified` keeps its plain meaning — "the
-- trace signature is valid" — and stays 1 for skip-verify rows;
-- `verification_source` records who attested it ('persist' = persist
-- ran verify_trace; 'edge' = delegated upstream, the #91 relay
-- skip-verify path). Every pre-V044 row was persist-verified, so
-- `DEFAULT 'persist'` backfills them correctly.

ALTER TABLE trace_events
    ADD COLUMN verification_source TEXT NOT NULL DEFAULT 'persist'
        CHECK (verification_source IN ('persist', 'edge'));
