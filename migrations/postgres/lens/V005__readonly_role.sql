-- V005 — Read-only role for analytical consumers (v0.3.2,
-- CIRISPersist#9).
--
-- Mission alignment (MISSION.md §2 — `store/`): persist owns the write
-- path; consumers compose analytical surfaces. Today every consumer
-- (lens science scripts, future partner sites, registry dashboards)
-- uses the same DSN as the write path. That works but conflates
-- privilege levels — a misconfigured analytics container could in
-- principle execute INSERT/UPDATE/DELETE on persist's substrate
-- tables, defeating the substrate-vs-policy separation.
--
-- This migration provisions `cirislens_reader` — a NOLOGIN role with
-- USAGE on the `cirislens` schema and SELECT on every existing +
-- future table. Operators provision a login user out-of-band and
-- GRANT cirislens_reader to it; the analytics path connects with
-- that login DSN, while the write path stays Engine-only on the
-- existing DATABASE_URL.
--
-- # Operator setup (out-of-band)
--
--   CREATE USER cirislens_analytics WITH PASSWORD '<vaulted>';
--   GRANT cirislens_reader TO cirislens_analytics;
--
-- Lens then sets `CIRISLENS_READ_DSN=postgres://cirislens_analytics:.../cirislens`
-- (or equivalent) and routes its analytical queries — Coherence
-- Ratchet detection, capacity scoring, N_eff, constraint-space
-- analyses, research scripts — through that connection.
--
-- # What's NOT in this role
--
-- - INSERT / UPDATE / DELETE on any table — write paths are
--   exclusively `Engine.receive_and_persist` (trace ingest) and
--   `Engine.put_*` (federation directory).
-- - Sequence access, function execution privileges — analytical SQL
--   doesn't need them.
-- - Access to other schemas (cirislens_derived for lens-owned tables,
--   pg_catalog for admin views, etc.). Scope stays narrow.
--
-- # Public schema contract
--
-- Which columns downstream consumers can rely on (and which may
-- change without notice) is documented in
-- `docs/PUBLIC_SCHEMA_CONTRACT.md`. Stability tiers:
--
--   - `stable`     — semver-guaranteed; removal/type change requires
--                    a major version + deprecation window
--   - `stable-ro`  — server-computed, downstream may read but writes
--                    are ignored (e.g. persist_row_hash)
--   - `internal`   — may change at any minor without notice;
--                    downstream MUST NOT depend
--
-- The doc + this GRANT are coupled: if a column is `internal`,
-- persist may revoke SELECT on it from the role; if `stable`, the
-- SELECT stays working across minor versions.
--
-- # Idempotency
--
-- The DO block makes role creation idempotent across re-runs of the
-- migration suite (refinery doesn't re-run V005 once recorded, but
-- the safety net is cheap and protects against operator-driven
-- replay scenarios). The GRANT statements are naturally idempotent.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cirislens_reader') THEN
        CREATE ROLE cirislens_reader NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA cirislens TO cirislens_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA cirislens TO cirislens_reader;

-- Future tables created in cirislens schema (v0.3.x+ migrations,
-- v0.4.0 wire-format consolidation, etc.) inherit SELECT for the
-- reader role automatically. ALTER DEFAULT PRIVILEGES applies to the
-- role that runs the CREATE TABLE — refinery runs migrations as the
-- DSN's user, so the operator must ensure their migration role grants
-- accordingly. Persist's V005 sets it for the migration role itself.
ALTER DEFAULT PRIVILEGES IN SCHEMA cirislens
    GRANT SELECT ON TABLES TO cirislens_reader;
