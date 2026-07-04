-- V092 — Counter-RII `consent_role` consumer-query index,
-- SQLite dialect (CIRISPersist#365, CC 3.4.7.2 `consent-counter`,
-- v12.7.0).
--
-- Postgres parity (postgres/lens/V092): same index + same intent, with
-- the following dialect translations:
--
--   PostgreSQL                          → SQLite
--   ─────────────────────────────────────────────────────────────────
--   COMMENT ON COLUMN ...               → (no equivalent — SQLite has no
--                                          column-comment facility; docs
--                                          live in source + the PG twin)
--
-- # No new column — the substrate already shipped in V020
--
-- See postgres/lens/V092 for the full rationale. Summary: CC 3.4.7.2
-- ratified `federation_keys.consent_role`, but V020 (the CIRISAgent#760
-- §RC "consent role lock") already added the column (`TEXT NOT NULL
-- DEFAULT 'unregistered'`; vocabulary unregistered / temporary /
-- partnered / anonymous / authorized_review / peer — SQLite's ALTER
-- cannot add a CHECK, so the vocabulary is enforced at the Rust
-- admission layer on BOTH backends for symmetry). v12.7.0 puts the
-- field on the wire (`KeyRecord.consent_role`, `None` ⇔ 'unregistered'),
-- adds the resolver + the OQ-1 overwrite surface (`set_consent_role`),
-- and ships this index. OQ-2 / OQ-3 detection signals are
-- consumer-applied (edge `ProbePatternObserver` / RATCHET).

-- ── Index ───────────────────────────────────────────────────────────
--
-- Partial index on rows that carry an assigned role — same intent as
-- the PG twin (a Counter-RII consumer querying by role). SQLite partial
-- indexes use `WHERE` exactly like Postgres.

CREATE INDEX IF NOT EXISTS federation_keys_consent_role
    ON federation_keys (consent_role)
    WHERE consent_role <> 'unregistered';
